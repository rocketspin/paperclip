import { describe, it, expect } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import {
  lookupHash,
  verificationHash,
  verifyToken,
  verifyWithArgon2Defense,
} from "../services/api-key-hash.ts";

describe("api-key-hash", () => {
  it("lookupHash is deterministic sha256 hex (matches legacy createHash)", () => {
    const token = "test-token-abc";
    const expected = createHash("sha256").update(token).digest("hex");
    expect(lookupHash(token)).toBe(expected);
  });

  it("verificationHash produces argon2id format", async () => {
    const hash = await verificationHash("some-token");
    expect(hash).toMatch(/^\$argon2id\$/);
  });

  it("verificationHash uses random salt — same input => different hash", async () => {
    const token = "same-input";
    const a = await verificationHash(token);
    const b = await verificationHash(token);
    expect(a).not.toBe(b);
  });

  it("verifyToken accepts correct token against argon2 hash", async () => {
    const token = randomBytes(32).toString("hex");
    const hash = await verificationHash(token);
    expect(await verifyToken(token, hash)).toBe(true);
  });

  it("verifyToken rejects wrong token against argon2 hash", async () => {
    const hash = await verificationHash("correct");
    expect(await verifyToken("wrong", hash)).toBe(false);
  });

  it("verifyToken accepts correct token against legacy sha256 hex (backward-compat)", async () => {
    const token = "legacy-token";
    const legacyHash = createHash("sha256").update(token).digest("hex");
    expect(await verifyToken(token, legacyHash)).toBe(true);
  });

  it("verifyToken rejects wrong token against sha256 hex", async () => {
    const legacyHash = createHash("sha256").update("correct").digest("hex");
    expect(await verifyToken("wrong", legacyHash)).toBe(false);
  });

  it("verifyWithArgon2Defense short-circuits true for null (legacy row)", async () => {
    expect(await verifyWithArgon2Defense("anything", null)).toBe(true);
  });

  it("verifyWithArgon2Defense verifies against non-null argon2 hash", async () => {
    const token = randomBytes(16).toString("hex");
    const hash = await verificationHash(token);
    expect(await verifyWithArgon2Defense(token, hash)).toBe(true);
    expect(await verifyWithArgon2Defense("not-the-token", hash)).toBe(false);
  });

  it("verifyWithArgon2Defense returns false on malformed argon2 hash", async () => {
    expect(await verifyWithArgon2Defense("token", "not-a-real-argon2-hash")).toBe(false);
  });
});
