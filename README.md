# Agent Games Agent — zkVerify (Proof Gatekeeper + Steal the VFY)

A production-shaped HTTP agent for the **zkVerify Agent Games** (protocol v1),
implementing both automated tracks in a single Node.js service with no web
framework (plain `http`):

- **Proof Gatekeeper** — decides APPROVE/REJECT for proof-gated payment tasks
  with deterministic trap checks and returns a Groth16 proof of the decision.
- **Steal the VFY** — plays turns from a committed strategy (Poseidon
  commitment over 8 strategy params + salt) and returns a policy proof per turn.

Every platform request is HMAC-authenticated and every response is signed.

## Setup

```bash
npm install
bash scripts/download-circuits.sh   # fetches the 4 official circuit artifacts
cp .env.example .env                # then fill in real values (never commit .env)
```

Circuit artifacts (downloaded into `circuits/`, kept out of git):

| File | Size |
|---|---|
| `gatekeeper.wasm` | ~1.7 MB |
| `gatekeeper_final.zkey` | ~0.3 MB |
| `vfy-policy.wasm` | ~2.9 MB |
| `vfy-policy_final.zkey` | ~0.8 MB |

Source: `https://agentgames.zkverify.io/circuits/<file>`

## Environment variables

| Variable | Required | Meaning |
|---|---|---|
| `PORT` | no (default `8080`) | Listen port. |
| `AGENT_GAMES_HMAC_SECRET` | yes (production) | Secret issued by the dashboard — see "Getting the HMAC secret" below. If unset, inbound verification is skipped and responses are unsigned (**local dev only**, a warning is logged). |
| `STEAL_STRATEGY_PARAMS` | no (default `5,50,0,0,0,0,0,0`) | 8 integers: `[extractAmount 1–10, fortifyThreshold, minOpponentBalance, mode (0 normal, 1 always HOLD), 0, 0, 0, 0]`. Params 4–7 must be 0. |
| `STEAL_STRATEGY_SALT` | yes (production) | Hex salt for the strategy commitment. If unset, a random salt is generated at startup and the commitment **changes on every restart** — fine for local tests, broken for a registered commitment. |

## Run

```bash
node server.js        # or: npm start
```

### Endpoints

- `GET /health` → `200 { ok: true, hmacConfigured, strategyCommitment, circuits: {...}, ... }`
- `POST /agent` (aliases `/gatekeeper`, `/steal` route to the same handler),
  dispatched by payload:
  - `{ type: "agent-games.preflight.v1", ... }` → `{ ok: true, protocolVersion: "v1" }`
  - `{ type: "agent-games.proof-gatekeeper.v1", task_id, input: {...} }` →
    `{ decision, reason_code, proof_tx, proof, public_signals }`
    (13 public signals; `proof`/`public_signals` omitted for `PROOF_REUSED`
    and `INVALID_TASK`)
  - `{ eventId: "steal-the-vfy", matchId, turn, state: {...}, strategyCommitment: { hash } }` →
    `{ matchId, turn, action, policyProof: { circuitVersion: "v1", proof, public_signals, publicInputsHash }, agentTimestamp, idempotencyKey }`
    (9 public signals; `action.amount` is present **only** for `EXTRACT`)

### HMAC (protocol v1)

- Inbound: header `x-agent-games-signature` must equal
  `HMAC-SHA256 hex(raw request body, AGENT_GAMES_HMAC_SECRET)`, verified with
  `crypto.timingSafeEqual` **before** JSON parsing. Mismatch → `401`.
- Outbound: every response carries `x-agent-games-signature` computed the same
  way over the raw response body (when the secret is set).

### Gatekeeper decision logic (first match wins)

1. `proof_vk != registered_vk` → REJECT `VK_SUBSTITUTION`
2. `proof_tx` already seen under a different `task_id` → REJECT `PROOF_REUSED` (no proof attached; replay tracking is in-memory)
3. `public_balance < minimum` → REJECT `THRESHOLD_MISMATCH`
4. `current_block >= expiry_block` → REJECT `EXPIRED_CONDITION`
5. `recipient != condition_recipient` → REJECT `RECIPIENT_MISMATCH`
6. `amount > max_transfer` → REJECT `AMOUNT_OVERFLOW`
7. otherwise → APPROVE `VALID_CONDITION`

Missing fields → REJECT `INVALID_TASK` (no proof). The proof is generated
locally with snarkjs (`groth16.fullProve`, gatekeeper circuit); the circuit
constrains the decision to its own evaluation, so a wrong verdict fails
witness generation — in that case the agent fails closed (an APPROVE becomes
REJECT `PROVER_ERROR`; a REJECT is returned without proof).

### Steal the VFY strategy

Default policy (params `5,50,0,0,0,0,0,0`, mode 0), evaluated in order:
balance below the fortify threshold (50) → `FORTIFY`; opponent balance
≤ min-opponent (0) → `HOLD`; otherwise `EXTRACT 5`. Mode 1 = always `HOLD`.

The strategy commitment is `Poseidon(params[0..7], salt)`:

```bash
STEAL_STRATEGY_PARAMS=5,50,0,0,0,0,0,0 STEAL_STRATEGY_SALT=<hex> npm run commitment
# -> 0x… (register this hash as the strategy commitment)
```

If a turn envelope pins a `strategyCommitment.hash` that does not match the
locally computed commitment, the agent responds `HOLD` without a proof.

## Tests

```bash
npm test   # node test-local.js
```

Starts the server on a test port with a test HMAC secret and a fixed test
salt, exports both verification keys from the zkeys
(`snarkjs zkey export verificationkey` → `circuits/*_vk.json`), then verifies
end-to-end: health, preflight signing (valid + bad signature → 401), all
Gatekeeper trap cases with `groth16.verify` on every proof, proof-reuse
behaviour, Steal EXTRACT/FORTIFY proofs, commitment-mismatch HOLD, and the
commitment script. All 19 checks passed locally (Node v24, proofs ~0.3–1.1 s
each).

## Deployment notes

- Needs **public HTTPS hosting that does not sleep** (e.g. Railway — see
  `railway.json`; a `Procfile` is also included). Free tiers that idle/sleep
  will miss tasks and turns. The platform requires a public HTTPS endpoint:
  no localhost, no private IPs, no custom ports.
- Hosting builds must fetch the circuits first: `railway.json` runs
  `bash scripts/download-circuits.sh` as a prestart step (the `Procfile` does
  the same inline).
- **Getting the HMAC secret:** after registering the agent in the Agent Games
  dashboard, open the agent settings and use **Rotate Secret** — the plaintext
  secret is shown **exactly once**. Set it as `AGENT_GAMES_HMAC_SECRET` in the
  hosting env and restart the service, then run preflight from the dashboard.
  Never commit the secret to the repository.
- Set `STEAL_STRATEGY_SALT` (fixed hex) in the hosting env **before**
  registering the strategy commitment, and register the hash printed by
  `npm run commitment` with the same env values.
- Register the full handler path as the endpoint (e.g. `https://<host>/agent`),
  not just the root — the platform checks `GET /health` first, then the endpoint.

## Project layout

```
server.js                  # HTTP server, HMAC, Gatekeeper + Steal handlers
strategy.js                # strategy params/salt + Poseidon commitment helpers
commitment.js              # `npm run commitment` — prints the strategy commitment
test-local.js              # end-to-end local test suite
scripts/download-circuits.sh
circuits/                  # official .wasm/.zkey artifacts (gitignored, downloaded)
railway.json, Procfile     # start config: node server.js
.env.example               # env template — no real secrets
```
