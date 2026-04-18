/**
 * API-key hashing for Paperclip agent keys.
 *
 * Why two hashes, not one:
 *   Paperclip tokens are `crypto.randomBytes(32)` — high-entropy random strings.
 *   The audit's "hash with bcrypt/argon2" recommendation targets low-entropy
 *   passwords vulnerable to rainbow tables. For random tokens, SHA-256 is
 *   cryptographically fine.
 *
 *   Defense-in-depth still helps though: if the `agent_api_keys` table is
 *   leaked, we don't want an attacker to just read `keyHash` and use it.
 *   So we store:
 *     - `keyHash`       (SHA-256 hex, indexed)  ← fast DB lookup
 *     - `keyHashArgon2` (argon2id hash)          ← expensive to brute-force
 *
 *   Verification flow:
 *     1. Compute sha256(token), query `WHERE keyHash = ?` (indexed, O(log n))
 *     2. If row has a non-null keyHashArgon2, also argon2.verify(token)
 *        against it; if mismatch, reject (defense against DB-leak attacker
 *        who somehow forged an SHA-256 collision or has a precomputed table)
 *     3. If row's keyHashArgon2 is null (legacy row), accept the SHA-256
 *        match alone — backward-compat for pre-existing keys.
 *
 * This yields: no API/client-visible change, no forced key rotation, O(log n)
 * lookup retained, argon2-level defense on all keys created after deploy.
 */

import { createHash, timingSafeEqual } from "node:crypto";
// argon2 is a native addon; require() ensures the binding is resolved at module
// load time rather than at first use (helps surface install problems early).
// eslint-disable-next-line @typescript-eslint/no-require-imports
import argon2 from "argon2";

// Argon2id params tuned for interactive verification (<100ms on typical
// hardware). We don't go heavier because verification happens on every
// authenticated request; a slower hash would add latency to every API call.
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB — OWASP's balanced recommendation
  timeCost: 2,
  parallelism: 1,
} as const;

/** Indexed lookup hash. Use for DB queries. */
export function lookupHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Expensive verification hash. Use alongside lookupHash when creating a key. */
export async function verificationHash(token: string): Promise<string> {
  return argon2.hash(token, ARGON2_OPTIONS);
}

/**
 * Verify a token against a stored hash. Works for both legacy (sha256 hex)
 * and new (argon2id) formats. Used by callers that haven't yet migrated to
 * the two-column lookup.
 */
export async function verifyToken(token: string, storedHash: string): Promise<boolean> {
  if (storedHash.startsWith("$argon2")) {
    try {
      return await argon2.verify(storedHash, token);
    } catch {
      return false;
    }
  }
  // Legacy SHA-256 hex path — timing-safe compare
  const expected = lookupHash(token);
  if (expected.length !== storedHash.length) return false;
  try {
    return timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(storedHash, "hex"));
  } catch {
    return false;
  }
}

/**
 * Combined helper for verification sites that have both columns available.
 * Pass `argon2Hash: null` for legacy rows where the column is null.
 *
 * Returns true only if the token matches both (a) the indexed sha256 path
 * which the caller already used for lookup, and (b) the argon2 hash if
 * present. For legacy null rows, the sha256 match the caller already did
 * is sufficient, so this short-circuits true.
 */
export async function verifyWithArgon2Defense(
  token: string,
  argon2Hash: string | null,
): Promise<boolean> {
  if (!argon2Hash) return true; // legacy row — trust the caller's sha256 match
  try {
    return await argon2.verify(argon2Hash, token);
  } catch {
    return false;
  }
}
