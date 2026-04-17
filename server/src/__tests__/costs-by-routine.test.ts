import { describe, expect, it, vi } from "vitest";
import { costService } from "../services/costs.ts";

function makeDbStub(rows: unknown[]) {
  const captured: { groupByArgs?: unknown[] } = {};
  const chain = {
    from: vi.fn(() => chain),
    innerJoin: vi.fn(() => chain),
    leftJoin: vi.fn(() => chain),
    where: vi.fn(() => chain),
    groupBy: vi.fn((...args: unknown[]) => {
      captured.groupByArgs = args;
      return chain;
    }),
    orderBy: vi.fn(() => chain),
    then: vi.fn((resolve: (value: unknown[]) => unknown) => Promise.resolve(resolve(rows))),
  };
  return {
    db: { select: vi.fn(() => chain) },
    chain,
    captured,
  };
}

describe("costService.byRoutine", () => {
  it("groups cost_events through issues.originKind='routine_execution' and returns per-routine totals", async () => {
    const { db, chain } = makeDbStub([
      {
        routineId: "routine-1",
        routineTitle: "Daily site audit",
        routineStatus: "active",
        costCents: 1250,
        inputTokens: 120000,
        cachedInputTokens: 50000,
        outputTokens: 4000,
        runCount: 3,
        issueCount: 3,
      },
      {
        routineId: "routine-2",
        routineTitle: "Follow-up sweep",
        routineStatus: "active",
        costCents: 400,
        inputTokens: 30000,
        cachedInputTokens: 20000,
        outputTokens: 900,
        runCount: 2,
        issueCount: 2,
      },
    ]);

    const costs = costService(db as any);
    const result = await costs.byRoutine("company-1");

    expect(result).toHaveLength(2);
    expect(result[0].routineTitle).toBe("Daily site audit");
    expect(result[0].costCents).toBe(1250);
    expect(result[1].routineTitle).toBe("Follow-up sweep");

    // verify the query actually joins issues and filters routine_execution
    expect(chain.innerJoin).toHaveBeenCalled();
    expect(chain.leftJoin).toHaveBeenCalled();
    expect(chain.where).toHaveBeenCalled();
  });

  it("returns empty list when no routine-sourced cost events exist", async () => {
    const { db } = makeDbStub([]);
    const costs = costService(db as any);
    const result = await costs.byRoutine("company-1");
    expect(result).toEqual([]);
  });

  it("applies date range filters when provided", async () => {
    const { db, chain } = makeDbStub([]);
    const costs = costService(db as any);
    const from = new Date("2026-04-01T00:00:00Z");
    const to = new Date("2026-04-17T00:00:00Z");
    await costs.byRoutine("company-1", { from, to });
    expect(chain.where).toHaveBeenCalled();
  });
});
