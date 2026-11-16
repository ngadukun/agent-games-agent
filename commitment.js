#!/usr/bin/env node
// Prints the Steal the VFY strategy commitment for the current env:
//   commitment = Poseidon(strategyParams[0..7], salt)  (0x 32-byte hex)
// Reads STEAL_STRATEGY_PARAMS and STEAL_STRATEGY_SALT from the environment.
// If STEAL_STRATEGY_SALT is unset, a RANDOM salt is generated for this run
// only — the printed commitment will NOT match a server started without the
// same fixed salt. Set STEAL_STRATEGY_SALT for a stable commitment.
import { getStrategy, toHex32 } from "./strategy.js";

const { params, saltEphemeral, commitment } = getStrategy();
if (saltEphemeral) {
  console.error(
    "WARNING: STEAL_STRATEGY_SALT is not set — using a random ephemeral salt. " +
      "This commitment is not reproducible. Set STEAL_STRATEGY_SALT (hex) for production."
  );
}
console.error(`strategyParams = [${params.join(", ")}]`);
console.log(toHex32(commitment));
