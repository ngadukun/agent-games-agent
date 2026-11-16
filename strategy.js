import crypto from "node:crypto";
import { poseidon9 } from "poseidon-lite";

// BN128 (alt_bn128) scalar field prime, used by both Groth16 circuits.
export const FIELD_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const DEFAULT_STRATEGY_PARAMS = "5,50,0,0,0,0,0,0";

/** Parse STEAL_STRATEGY_PARAMS ("5,50,0,0,0,0,0,0") into 8 BigInt field values. */
export function parseStrategyParams(raw) {
  const src = (raw ?? DEFAULT_STRATEGY_PARAMS).trim();
  const parts = src === "" ? [] : src.split(",").map((s) => BigInt(s.trim()));
  while (parts.length < 8) parts.push(0n);
  return parts.slice(0, 8).map((v) => ((v % FIELD_P) + FIELD_P) % FIELD_P);
}

let _saltCache = null;

/**
 * Resolve the strategy salt (field element).
 * STEAL_STRATEGY_SALT is a hex string. If unset, a random salt is generated
 * once per process and flagged ephemeral — for production the salt MUST be
 * fixed via env, otherwise the commitment changes on every restart.
 */
export function getSalt() {
  if (_saltCache) return _saltCache;
  const raw = process.env.STEAL_STRATEGY_SALT;
  if (raw && raw.trim() !== "") {
    const hex = raw.trim().toLowerCase().replace(/^0x/, "");
    _saltCache = { salt: BigInt("0x" + hex) % FIELD_P, ephemeral: false };
  } else {
    const rnd = BigInt("0x" + crypto.randomBytes(32).toString("hex")) % FIELD_P;
    _saltCache = { salt: rnd, ephemeral: true };
  }
  return _saltCache;
}

/** Commitment = Poseidon(strategyParams[0..7], salt) as a BigInt field element. */
export function computeCommitment(params, salt) {
  return poseidon9([...params, salt]);
}

/** Format a field element / BigInt as a 0x-prefixed 32-byte hex string. */
export function toHex32(v) {
  return "0x" + v.toString(16).padStart(64, "0");
}

export function getStrategy() {
  const params = parseStrategyParams(process.env.STEAL_STRATEGY_PARAMS);
  const { salt, ephemeral } = getSalt();
  const commitment = computeCommitment(params, salt);
  return { params, salt, saltEphemeral: ephemeral, commitment, commitmentHex: toHex32(commitment) };
}
