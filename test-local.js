#!/usr/bin/env node
/**
 * Local end-to-end tests (no real secrets, no network beyond localhost
 * except the one-time snarkjs CLI vk export which is local).
 *
 * Starts the server on a test port with a TEST HMAC secret and a FIXED test
 * strategy salt, then checks:
 *   1. GET /health
 *   2. Preflight HMAC (valid -> 200 + signed response; bad sig -> 401)
 *   3. Gatekeeper: 6 decision cases, each with local groth16.verify,
 *      plus proof-reuse behaviour
 *   4. Steal the VFY: EXTRACT / FORTIFY cases with local groth16.verify,
 *      plus commitment-mismatch -> HOLD without proof
 *   5. `npm run commitment` prints the same 0x commitment the server reports
 */
import { spawn, execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 18099;
const BASE = `http://localhost:${PORT}`;
const SECRET = "test-hmac-secret-local-only";
const SALT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PARAMS = "5,50,0,0,0,0,0,0";

const results = [];
function check(name, cond, detail = "") {
  results.push({ name, pass: Boolean(cond), detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}
async function post(obj, sigOverride) {
  const body = JSON.stringify(obj);
  const t0 = Date.now();
  const res = await fetch(BASE + "/agent", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-agent-games-signature": sigOverride ?? sign(body) },
    body,
  });
  const raw = await res.text();
  let json; try { json = JSON.parse(raw); } catch { json = {}; }
  return { status: res.status, body: json, raw, sig: res.headers.get("x-agent-games-signature"), ms: Date.now() - t0 };
}

// --- export verification keys -------------------------------------------------
execSync(`npx snarkjs zkey export verificationkey circuits/gatekeeper_final.zkey circuits/gatekeeper_vk.json`, { cwd: __dirname, stdio: "pipe" });
execSync(`npx snarkjs zkey export verificationkey circuits/vfy-policy_final.zkey circuits/vfy-policy_vk.json`, { cwd: __dirname, stdio: "pipe" });
const gkVk = JSON.parse(fs.readFileSync(path.join(__dirname, "circuits", "gatekeeper_vk.json"), "utf8"));
const vfyVk = JSON.parse(fs.readFileSync(path.join(__dirname, "circuits", "vfy-policy_vk.json"), "utf8"));
console.log("Verification keys exported to circuits/*_vk.json");

// --- start server --------------------------------------------------------------
const server = spawn("node", ["server.js"], {
  cwd: __dirname,
  env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, STEAL_STRATEGY_SALT: SALT, STEAL_STRATEGY_PARAMS: PARAMS },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverLog = "";
server.stdout.on("data", (d) => (serverLog += d));
server.stderr.on("data", (d) => (serverLog += d));

async function waitHealth() {
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(BASE + "/health"); if (r.ok) return await r.json(); } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("server did not come up. Log:\n" + serverLog);
}

let commitment;
try {
  // 1. Health
  const health = await waitHealth();
  check("GET /health ok:true", health.ok === true);
  check("health hmacConfigured", health.hmacConfigured === true);
  commitment = health.strategyCommitment;
  check("health strategyCommitment is 0x32-byte hex", /^0x[0-9a-f]{64}$/.test(commitment), commitment);

  // 2. Preflight
  let r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  check("preflight valid sig -> 200 {ok:true, protocolVersion:v1}", r.status === 200 && r.body.ok === true && r.body.protocolVersion === "v1");
  check("preflight response signature valid", r.sig === sign(r.raw));
  r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", nonce: "x" }, "deadbeef".repeat(8));
  check("preflight bad sig -> 401", r.status === 401, `status ${r.status}`);

  // 3. Gatekeeper
  const VK = "0x7d91aabbccdd11223344556677889900aabbccdd11223344556677889900112233";
  let n = 0;
  function gkTask(overrides = {}, inputOverrides = {}) {
    n += 1;
    return {
      type: "agent-games.proof-gatekeeper.v1",
      task_id: `gk_test_${n}`,
      mode: "competition",
      issued_at: new Date().toISOString(),
      deadline_at: new Date(Date.now() + 60000).toISOString(),
      input: {
        registered_vk: VK, proof_vk: VK, minimum: "1000", public_balance: "1460",
        expiry_block: 8430000, current_block: 8420000,
        recipient: "0xDe42aabbccdd00112233445566778899009f01",
        condition_recipient: "0xDe42aabbccdd00112233445566778899009f01",
        amount: "500", max_transfer: "1000", proof_tx: `0xa8test${n}`,
        ...inputOverrides,
      },
      ...overrides,
    };
  }
  async function gkCase(name, task, decision, reason, expectProof = true) {
    const res = await post(task);
    let ok = res.status === 200 && res.body.decision === decision && res.body.reason_code === reason;
    let detail = `${res.body.decision}/${res.body.reason_code}, ${res.ms}ms (http incl. prove)`;
    if (expectProof) {
      ok = ok && Boolean(res.body.proof) && Array.isArray(res.body.public_signals) && res.body.public_signals.length === 13;
      if (res.body.proof) {
        const verified = await groth16.verify(gkVk, res.body.public_signals, res.body.proof);
        ok = ok && verified;
        detail += `, signals=${res.body.public_signals?.length}, verify=${verified}`;
      }
    } else {
      ok = ok && !("proof" in res.body) && !("public_signals" in res.body);
      detail += ", no proof fields (expected)";
    }
    check(`gatekeeper ${name}`, ok, detail);
    return res.body;
  }

  await gkCase("valid -> APPROVE/VALID_CONDITION", gkTask(), "APPROVE", "VALID_CONDITION");
  await gkCase("vk mismatch -> VK_SUBSTITUTION", gkTask({}, { proof_vk: "0x13ff00aa" }), "REJECT", "VK_SUBSTITUTION");
  await gkCase("balance 500<1000 -> THRESHOLD_MISMATCH", gkTask({}, { public_balance: "500" }), "REJECT", "THRESHOLD_MISMATCH");
  await gkCase("current==expiry -> EXPIRED_CONDITION", gkTask({}, { current_block: 8430000 }), "REJECT", "EXPIRED_CONDITION");
  await gkCase("recipient mismatch -> RECIPIENT_MISMATCH", gkTask({}, { recipient: "0xBeef0011223344556677889900aabbccddeeff00" }), "REJECT", "RECIPIENT_MISMATCH");
  await gkCase("amount 1500>1000 -> AMOUNT_OVERFLOW", gkTask({}, { amount: "1500" }), "REJECT", "AMOUNT_OVERFLOW");

  // Reuse: same proof_tx, first under task A, retry of A is fine, new task B is reuse.
  const reuseTx = "0xa8reuse0001";
  const taskA = gkTask({}, { proof_tx: reuseTx });
  await gkCase("reuse setup (task A first use)", taskA, "APPROVE", "VALID_CONDITION");
  await gkCase("reuse retry (same task_id, not reuse)", taskA, "APPROVE", "VALID_CONDITION");
  const taskB = gkTask({}, { proof_tx: reuseTx });
  await gkCase("reuse under new task_id -> PROOF_REUSED (no proof)", taskB, "REJECT", "PROOF_REUSED", false);

  // 4. Steal the VFY
  function stealTurn(overrides = {}) {
    return {
      protocolVersion: "v1", eventId: "steal-the-vfy", mode: "competition",
      matchId: "9f4e1b2a-1111-4222-8333-444455556666", turn: 3,
      issuedAt: new Date().toISOString(), deadlineAt: new Date(Date.now() + 300000).toISOString(),
      state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      strategyCommitment: { hash: commitment }, resolverVersion: "v1", nonce: "3c2f1a",
      ...overrides,
    };
  }
  r = await post(stealTurn());
  {
    const pp = r.body.policyProof || {};
    const verified = pp.proof ? await groth16.verify(vfyVk, pp.public_signals, pp.proof) : false;
    check("steal EXTRACT 5 (self 95>=50, opp 105>0)",
      r.status === 200 && r.body.action?.type === "EXTRACT" && r.body.action?.amount === 5 && pp.circuitVersion === "v1" &&
      Array.isArray(pp.public_signals) && pp.public_signals.length === 9 && /^0x[0-9a-f]{64}$/.test(pp.publicInputsHash || "") && verified,
      `${JSON.stringify(r.body.action)}, signals=${pp.public_signals?.length}, verify=${verified}, ${r.ms}ms`);
  }
  r = await post(stealTurn({ turn: 4, state: { selfBalance: "30", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null } }));
  {
    const pp = r.body.policyProof || {};
    const verified = pp.proof ? await groth16.verify(vfyVk, pp.public_signals, pp.proof) : false;
    check("steal FORTIFY (self 30<50), no amount key",
      r.status === 200 && r.body.action?.type === "FORTIFY" && !("amount" in (r.body.action || {})) && verified,
      `${JSON.stringify(r.body.action)}, verify=${verified}, ${r.ms}ms`);
  }
  r = await post(stealTurn({ strategyCommitment: { hash: "0x" + "00".repeat(32) } }));
  check("steal commitment mismatch -> HOLD without proof",
    r.status === 200 && r.body.action?.type === "HOLD" && !("policyProof" in r.body) && !("amount" in (r.body.action || {})),
    JSON.stringify(r.body.action));

  // 5. commitment script
  const out = execSync("npm run --silent commitment", {
    cwd: __dirname,
    env: { ...process.env, STEAL_STRATEGY_SALT: SALT, STEAL_STRATEGY_PARAMS: PARAMS },
  }).toString().trim().split("\n").pop().trim();
  check("npm run commitment prints server commitment", /^0x[0-9a-f]{64}$/.test(out) && out === commitment, out);
} finally {
  server.kill("SIGTERM");
}

const failed = results.filter((x) => !x.pass);
console.log(`\n=== ${results.length - failed.length}/${results.length} checks passed ===`);
if (serverLog.trim()) console.log("--- server log ---\n" + serverLog.trim().split("\n").slice(-6).join("\n"));
process.exit(failed.length ? 1 : 0);
