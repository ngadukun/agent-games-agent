#!/usr/bin/env node
/**
 * zkVerify Agent Games agent — protocol v1
 * Tracks: Proof Gatekeeper + Steal the VFY.
 *
 * Plain Node http server (no framework).
 *   GET  /health                    -> { ok: true, ... }
 *   POST /agent | /gatekeeper | /steal  (same handler, routed by payload)
 *
 * HMAC: inbound `x-agent-games-signature` = HMAC-SHA256 hex over the RAW
 * request body with AGENT_GAMES_HMAC_SECRET, verified (timingSafeEqual)
 * BEFORE JSON parsing; mismatch -> 401. If the secret is unset, verification
 * is skipped with a startup warning (local dev only). Every response is
 * signed the same way over the raw response body when the secret is set.
 */
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";
import { keccak256 } from "js-sha3";
import { FIELD_P, getStrategy, toHex32 } from "./strategy.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || null;

const CIRCUITS = {
  gatekeeperWasm: path.join(__dirname, "circuits", "gatekeeper.wasm"),
  gatekeeperZkey: path.join(__dirname, "circuits", "gatekeeper_final.zkey"),
  vfyWasm: path.join(__dirname, "circuits", "vfy-policy.wasm"),
  vfyZkey: path.join(__dirname, "circuits", "vfy-policy_final.zkey"),
};

const strategy = getStrategy();

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}
function warn(...args) {
  console.warn(new Date().toISOString(), "WARN", ...args);
}

if (!HMAC_SECRET) {
  warn("AGENT_GAMES_HMAC_SECRET is not set — inbound HMAC verification DISABLED and responses unsigned (local dev only).");
}
if (strategy.saltEphemeral) {
  warn("STEAL_STRATEGY_SALT is not set — generated an EPHEMERAL strategy salt for this process. Commitment will change on restart. Set STEAL_STRATEGY_SALT (hex) for production.");
}
log(`Steal the VFY strategy params: [${strategy.params.join(", ")}]`);
log(`Steal the VFY strategy commitment: ${strategy.commitmentHex}`);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hmacHex(secret, data) {
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  const headers = { "Content-Type": "application/json" };
  if (HMAC_SECRET) headers["x-agent-games-signature"] = hmacHex(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

/** Convert a hex (0x…) / decimal string / number to a BN128 field element (decimal string). */
function toField(v) {
  let b;
  if (typeof v === "bigint") b = v;
  else if (typeof v === "number") b = BigInt(v);
  else if (typeof v === "string") {
    const s = v.trim();
    b = /^0x/i.test(s) ? BigInt(s) : BigInt(s);
  } else throw new Error(`toField: unsupported type ${typeof v}`);
  return (((b % FIELD_P) + FIELD_P) % FIELD_P).toString();
}

function randomField() {
  return (BigInt("0x" + crypto.randomBytes(32).toString("hex")) % FIELD_P).toString();
}

/** keccak256 of the UTF-8 bytes of a string, as a field element (decimal string). */
function keccakField(text) {
  const hex = keccak256(text);
  return (BigInt("0x" + hex) % FIELD_P).toString();
}

function pad32(v) {
  return v.toString(16).padStart(64, "0");
}

// ---------------------------------------------------------------------------
// Proof Gatekeeper
// ---------------------------------------------------------------------------

// proof_tx (lowercased) -> first task_id that used it (replay detection).
const seenProofTx = new Map();

const GK_REQUIRED = [
  "registered_vk", "proof_vk", "minimum", "public_balance", "expiry_block",
  "current_block", "recipient", "condition_recipient", "amount",
  "max_transfer", "proof_tx",
];

async function gatekeeperProve(input, taskId, decisionStr) {
  const witness = {
    registeredVkHash: toField(input.registered_vk),
    proofVkHash: toField(input.proof_vk),
    minimum: toField(input.minimum),
    publicBalance: toField(input.public_balance),
    expiryBlock: toField(input.expiry_block),
    currentBlock: toField(input.current_block),
    recipient: toField(input.recipient),
    conditionRecipient: toField(input.condition_recipient),
    amount: toField(input.amount),
    maxTransfer: toField(input.max_transfer),
    decision: decisionStr,
    taskId: keccakField(String(taskId ?? "")),
    salt: randomField(),
  };
  const { proof, publicSignals } = await groth16.fullProve(
    witness,
    CIRCUITS.gatekeeperWasm,
    CIRCUITS.gatekeeperZkey
  );
  return { proof, publicSignals };
}

async function handleGatekeeper(payload) {
  const input = payload.input || {};
  const taskId = payload.task_id;

  const missing = GK_REQUIRED.filter(
    (k) => input[k] === undefined || input[k] === null || input[k] === ""
  );
  if (missing.length > 0) {
    const out = { decision: "REJECT", reason_code: "INVALID_TASK" };
    if (input.proof_tx !== undefined) out.proof_tx = input.proof_tx;
    return out;
  }

  let decision, reason_code;

  // 1. VK substitution
  if (String(input.proof_vk).toLowerCase() !== String(input.registered_vk).toLowerCase()) {
    decision = "REJECT"; reason_code = "VK_SUBSTITUTION";
  } else {
    // 2. Proof reuse (record at this step; same task_id retry is not reuse)
    const key = String(input.proof_tx).toLowerCase();
    if (seenProofTx.has(key) && seenProofTx.get(key) !== taskId) {
      // No proof/public_signals for PROOF_REUSED.
      return { decision: "REJECT", reason_code: "PROOF_REUSED", proof_tx: input.proof_tx };
    }
    seenProofTx.set(key, taskId);

    // 3. Threshold
    if (BigInt(input.public_balance) < BigInt(input.minimum)) {
      decision = "REJECT"; reason_code = "THRESHOLD_MISMATCH";
    // 4. Expiry
    } else if (BigInt(input.current_block) >= BigInt(input.expiry_block)) {
      decision = "REJECT"; reason_code = "EXPIRED_CONDITION";
    // 5. Recipient
    } else if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase()) {
      decision = "REJECT"; reason_code = "RECIPIENT_MISMATCH";
    // 6. Amount overflow
    } else if (BigInt(input.amount) > BigInt(input.max_transfer)) {
      decision = "REJECT"; reason_code = "AMOUNT_OVERFLOW";
    // 7. Valid
    } else {
      decision = "APPROVE"; reason_code = "VALID_CONDITION";
    }
  }

  // Prove the decision. The circuit constrains `decision` to its own
  // evaluation of the five checks, so a wrong decision fails witness
  // generation here. PROOF_REUSED never reaches this point (not in circuit).
  try {
    const { proof, publicSignals } = await gatekeeperProve(
      input, taskId, decision === "APPROVE" ? "1" : "0"
    );
    return { decision, reason_code, proof_tx: input.proof_tx, proof, public_signals: publicSignals };
  } catch (err) {
    log(`gatekeeper prover error (task ${taskId}, verdict ${decision}/${reason_code}): ${err.message}`);
    if (decision === "APPROVE") {
      // Fail closed.
      return { decision: "REJECT", reason_code: "PROVER_ERROR", proof_tx: input.proof_tx };
    }
    return { decision, reason_code, proof_tx: input.proof_tx };
  }
}

// ---------------------------------------------------------------------------
// Steal the VFY
// ---------------------------------------------------------------------------

const ACTION_ENUM = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

function matchIdField(matchId) {
  const hex = String(matchId).replace(/-/g, "");
  return BigInt("0x" + hex) % FIELD_P;
}

function computePublicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, actionEnum, amount }) {
  const values = [
    commitment,
    matchIdField(matchId),
    BigInt(turn),
    BigInt(selfBalance),
    BigInt(opponentBalance),
    actionEnum,
    amount,
    1n, // circuitVersion v1
  ];
  const bytes = Buffer.from(values.map(pad32).join(""), "hex");
  return "0x" + keccak256([...bytes]);
}

function stealBaseResponse(payload, actionType, amount) {
  const action = { type: actionType };
  if (actionType === "EXTRACT") action.amount = amount;
  return {
    matchId: payload.matchId,
    turn: payload.turn,
    action,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: crypto.randomUUID(),
  };
}

async function handleSteal(payload) {
  const state = payload.state || {};
  const params = strategy.params;

  // Commitment check: if the envelope pins a commitment and it is not ours,
  // we cannot produce a valid policy proof — respond HOLD without proof.
  const envelopeHash = payload.strategyCommitment?.hash;
  if (envelopeHash !== undefined && envelopeHash !== null && envelopeHash !== "") {
    let matches = false;
    try { matches = BigInt(envelopeHash) === strategy.commitment; }
    catch { matches = String(envelopeHash).toLowerCase() === strategy.commitmentHex; }
    if (!matches) {
      log(`steal: commitment mismatch (envelope ${envelopeHash} != local ${strategy.commitmentHex}) — HOLD without proof`);
      return stealBaseResponse(payload, "HOLD");
    }
  }

  const self = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  const mode = params[3];

  let actionType;
  if (mode === 1n) actionType = "HOLD";
  else if (self < params[1]) actionType = "FORTIFY";
  else if (opp <= params[2]) actionType = "HOLD";
  else actionType = "EXTRACT";

  const actionEnum = ACTION_ENUM[actionType];
  const amount = actionType === "EXTRACT" ? params[0] : 0n;

  const witness = {
    // public
    commitment: strategy.commitment.toString(),
    matchId: matchIdField(payload.matchId).toString(),
    turnNumber: toField(payload.turn),
    selfBalance: toField(state.selfBalance),
    opponentBalance: toField(state.opponentBalance),
    action: actionEnum.toString(),
    amount: amount.toString(),
    circuitVersion: "1",
    // private
    salt: strategy.salt.toString(),
    strategyParams: params.map((v) => v.toString()),
  };

  try {
    const { proof, publicSignals } = await groth16.fullProve(
      witness,
      CIRCUITS.vfyWasm,
      CIRCUITS.vfyZkey
    );
    const publicInputsHash = computePublicInputsHash({
      commitment: strategy.commitment,
      matchId: payload.matchId,
      turn: payload.turn,
      selfBalance: state.selfBalance,
      opponentBalance: state.opponentBalance,
      actionEnum,
      amount,
    });
    const out = stealBaseResponse(
      payload, actionType, actionType === "EXTRACT" ? Number(params[0]) : undefined
    );
    out.policyProof = {
      circuitVersion: "v1",
      proof,
      public_signals: publicSignals,
      publicInputsHash,
    };
    // Response field order in the spec example: policyProof before timestamps.
    return {
      matchId: out.matchId,
      turn: out.turn,
      action: out.action,
      policyProof: out.policyProof,
      agentTimestamp: out.agentTimestamp,
      idempotencyKey: out.idempotencyKey,
    };
  } catch (err) {
    // Fail closed: HOLD without proof (platform resolves missing proof as HOLD).
    log(`steal prover error (match ${payload.matchId} turn ${payload.turn}): ${err.message}`);
    return stealBaseResponse(payload, "HOLD");
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

async function handlePost(req, res) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks);

  // Verify HMAC over the RAW body BEFORE parsing JSON.
  if (HMAC_SECRET) {
    const given = req.headers["x-agent-games-signature"] || "";
    const expected = hmacHex(HMAC_SECRET, raw);
    const a = Buffer.from(String(given));
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return sendJson(res, 401, { error: "invalid signature" });
    }
  }

  let payload;
  try {
    payload = JSON.parse(raw.toString("utf8"));
  } catch {
    return sendJson(res, 400, { error: "invalid json" });
  }

  try {
    if (payload.type === "agent-games.preflight.v1") {
      return sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    }
    if (payload.type === "agent-games.proof-gatekeeper.v1") {
      return sendJson(res, 200, await handleGatekeeper(payload));
    }
    if (payload.eventId === "steal-the-vfy") {
      return sendJson(res, 200, await handleSteal(payload));
    }
    return sendJson(res, 400, { error: "unknown payload type" });
  } catch (err) {
    log(`handler error: ${err.stack || err.message}`);
    return sendJson(res, 500, { error: "internal error" });
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (req.method === "GET" && url.pathname === "/health") {
    return sendJson(res, 200, {
      ok: true,
      service: "agent-games-agent",
      protocolVersion: "v1",
      hmacConfigured: Boolean(HMAC_SECRET),
      strategyCommitment: strategy.commitmentHex,
      strategySaltEphemeral: strategy.saltEphemeral,
      circuits: {
        gatekeeperWasm: fs.existsSync(CIRCUITS.gatekeeperWasm),
        gatekeeperZkey: fs.existsSync(CIRCUITS.gatekeeperZkey),
        vfyPolicyWasm: fs.existsSync(CIRCUITS.vfyWasm),
        vfyPolicyZkey: fs.existsSync(CIRCUITS.vfyZkey),
      },
      uptimeSeconds: Math.round(process.uptime()),
    });
  }
  if (req.method === "POST" && ["/agent", "/gatekeeper", "/steal"].includes(url.pathname)) {
    handlePost(req, res).catch((err) => {
      log(`post error: ${err.stack || err.message}`);
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
    });
    return;
  }
  return sendJson(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  log(`agent-games-agent listening on port ${PORT} (POST /agent, GET /health)`);
});
