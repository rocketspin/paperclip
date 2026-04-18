import type { Request, Response, NextFunction } from "express";

/**
 * Sliding-window in-memory rate limiter for Express routes.
 *
 * Paperclip runs as a single instance, so an in-memory limiter is sufficient
 * and avoids pulling in a new runtime dependency. For multi-instance
 * deployments this would need to be swapped for a shared store.
 *
 * Keying strategy: `ip|routeTag` so two different rate-limited routes don't
 * share a bucket. Falls back to "unknown" when Express can't determine the
 * remote IP (proxy misconfig, unit tests without `req.ip`).
 *
 * Usage:
 *   const limit = rateLimit({ max: 5, windowMs: 60_000, tag: "agent-create" });
 *   router.post("/companies/:companyId/agents", limit, validate(schema), handler);
 *
 * Response on limit hit: HTTP 429 with `Retry-After` header (seconds).
 */

export interface RateLimitOptions {
  /** max requests per window per key */
  max: number;
  /** window size in milliseconds */
  windowMs: number;
  /** identifier included in the bucket key, avoids cross-endpoint contamination */
  tag: string;
  /** optional custom key deriver (default: req.ip) */
  keyFn?: (req: Request) => string;
}

interface Bucket {
  timestamps: number[];
}

const buckets = new Map<string, Bucket>();

/** For tests — clear all buckets between cases. */
export function __resetRateLimitBuckets() {
  buckets.clear();
}

export function rateLimit(opts: RateLimitOptions) {
  const { max, windowMs, tag, keyFn } = opts;
  if (max <= 0) throw new Error("rateLimit: max must be > 0");
  if (windowMs <= 0) throw new Error("rateLimit: windowMs must be > 0");

  return function rateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
    const ip = (keyFn ? keyFn(req) : req.ip) || "unknown";
    const key = `${ip}|${tag}`;
    const now = Date.now();
    const cutoff = now - windowMs;

    const bucket = buckets.get(key) ?? { timestamps: [] };
    // Drop old timestamps
    bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);

    if (bucket.timestamps.length >= max) {
      const oldest = bucket.timestamps[0];
      const retryAfterMs = Math.max(0, windowMs - (now - oldest));
      const retryAfterSec = Math.ceil(retryAfterMs / 1000);
      res.setHeader("Retry-After", String(retryAfterSec));
      res.status(429).json({
        error: "Too many requests",
        retryAfterSeconds: retryAfterSec,
      });
      return;
    }

    bucket.timestamps.push(now);
    buckets.set(key, bucket);
    next();
  };
}

/** Preset limits for sensitive routes. Numbers are intentionally conservative. */
export const rateLimits = {
  /** Agent creation — resource-intensive, attacker could mass-create agents. */
  agentCreate: () => rateLimit({ max: 10, windowMs: 60_000, tag: "agent-create" }),

  /** Agent hire request — similar concern to direct create. */
  agentHire: () => rateLimit({ max: 10, windowMs: 60_000, tag: "agent-hire" }),

  /** API key creation — credential-grinding attack surface. */
  apiKeyCreate: () => rateLimit({ max: 5, windowMs: 60_000, tag: "api-key-create" }),

  /** Board claim — bootstrap, should almost never fire repeatedly. */
  boardClaim: () => rateLimit({ max: 3, windowMs: 5 * 60_000, tag: "board-claim" }),

  /** CLI auth challenge — brute-force target, tight limit. */
  cliAuth: () => rateLimit({ max: 20, windowMs: 60_000, tag: "cli-auth" }),
};
