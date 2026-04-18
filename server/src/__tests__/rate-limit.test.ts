import { describe, it, expect, beforeEach, vi } from "vitest";
import { rateLimit, __resetRateLimitBuckets } from "../middleware/rate-limit.ts";

function makeReqRes(ip: string = "1.2.3.4") {
  const req: any = { ip };
  const headers: Record<string, string> = {};
  const res: any = {
    statusCode: 200,
    body: null as any,
    setHeader: vi.fn((k: string, v: string) => {
      headers[k] = v;
    }),
    status: vi.fn(function status(this: any, code: number) {
      this.statusCode = code;
      return this;
    }),
    json: vi.fn(function json(this: any, body: any) {
      this.body = body;
      return this;
    }),
    headers,
  };
  const next = vi.fn();
  return { req, res, next };
}

describe("rateLimit middleware", () => {
  beforeEach(() => {
    __resetRateLimitBuckets();
  });

  it("allows up to max requests in the window, then blocks with 429", () => {
    const mw = rateLimit({ max: 3, windowMs: 60_000, tag: "test" });

    for (let i = 0; i < 3; i += 1) {
      const { req, res, next } = makeReqRes();
      mw(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(res.statusCode).toBe(200);
    }

    // 4th should block
    const { req, res, next } = makeReqRes();
    mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(429);
    expect(res.body).toMatchObject({ error: "Too many requests" });
    expect(res.headers["Retry-After"]).toBeDefined();
    expect(Number(res.headers["Retry-After"])).toBeGreaterThan(0);
  });

  it("isolates buckets by tag", () => {
    const mwA = rateLimit({ max: 2, windowMs: 60_000, tag: "alpha" });
    const mwB = rateLimit({ max: 2, windowMs: 60_000, tag: "beta" });

    // Fill bucket A
    for (let i = 0; i < 2; i += 1) {
      const { req, res, next } = makeReqRes();
      mwA(req, res, next);
      expect(res.statusCode).toBe(200);
    }
    // A now blocks
    const a3 = makeReqRes();
    mwA(a3.req, a3.res, a3.next);
    expect(a3.res.statusCode).toBe(429);

    // B is still fine
    const b1 = makeReqRes();
    mwB(b1.req, b1.res, b1.next);
    expect(b1.next).toHaveBeenCalled();
  });

  it("isolates buckets by ip", () => {
    const mw = rateLimit({ max: 1, windowMs: 60_000, tag: "per-ip" });

    // IP 1 hits limit
    const a = makeReqRes("10.0.0.1");
    mw(a.req, a.res, a.next);
    expect(a.res.statusCode).toBe(200);
    const a2 = makeReqRes("10.0.0.1");
    mw(a2.req, a2.res, a2.next);
    expect(a2.res.statusCode).toBe(429);

    // IP 2 is not affected
    const b = makeReqRes("10.0.0.2");
    mw(b.req, b.res, b.next);
    expect(b.res.statusCode).toBe(200);
  });

  it("releases slots as the window slides", () => {
    const mw = rateLimit({ max: 2, windowMs: 100, tag: "sliding" });

    const r1 = makeReqRes();
    mw(r1.req, r1.res, r1.next);
    const r2 = makeReqRes();
    mw(r2.req, r2.res, r2.next);
    const r3 = makeReqRes();
    mw(r3.req, r3.res, r3.next);
    expect(r3.res.statusCode).toBe(429);

    return new Promise<void>((resolve) => {
      setTimeout(() => {
        const r4 = makeReqRes();
        mw(r4.req, r4.res, r4.next);
        expect(r4.res.statusCode).toBe(200);
        resolve();
      }, 120);
    });
  });

  it("falls back to 'unknown' when req.ip is missing", () => {
    const mw = rateLimit({ max: 1, windowMs: 60_000, tag: "no-ip" });
    const { req, res, next } = makeReqRes();
    delete req.ip;
    mw(req, res, next);
    expect(next).toHaveBeenCalled();
    // Second hit from same 'unknown' bucket should block
    const r2 = makeReqRes();
    delete r2.req.ip;
    mw(r2.req, r2.res, r2.next);
    expect(r2.res.statusCode).toBe(429);
  });

  it("rejects invalid options at construction time", () => {
    expect(() => rateLimit({ max: 0, windowMs: 1000, tag: "x" })).toThrow();
    expect(() => rateLimit({ max: 1, windowMs: 0, tag: "x" })).toThrow();
  });
});
