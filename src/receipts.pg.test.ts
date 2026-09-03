/**
 * Integration check of the Postgres store. Runs only when RECEIPTS_TEST_DSN names
 * a throwaway database, e.g.
 *   docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=x postgres:16-alpine
 *   RECEIPTS_TEST_DSN=postgresql://postgres:x@localhost:55432/postgres npm test
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PostgresReceiptStore } from "./receipts.js";

const dsn = process.env.RECEIPTS_TEST_DSN;

test("postgres store: claim/complete/replay/conflict/in-flight/release, and two concurrent claims yield one miss", { skip: !dsn }, async () => {
  const s = new PostgresReceiptStore(dsn!);
  const key = `t-${Date.now()}`;
  try {
    assert.deepEqual(await s.claim(key, "alice", "create_invoice"), { kind: "miss" });
    const inflight = await s.claim(key, "alice", "create_invoice");
    assert.equal(inflight.kind, "in_flight");
    const result = { content: [{ type: "text", text: "{\"id\":42,\"invoiceNumber\":7}" }] };
    await s.complete(key, result);
    const again = await s.claim(key, "alice", "create_invoice");
    assert.equal(again.kind, "replay");
    assert.deepEqual((again as { result: unknown }).result, result);
    assert.deepEqual(await s.claim(key, "bob", "create_invoice"), { kind: "conflict" });
    assert.deepEqual(await s.claim(key, "alice", "create_time_entry"), { kind: "conflict" });
    await s.release(key); // completed → must NOT be released
    assert.equal((await s.claim(key, "alice", "create_invoice")).kind, "replay");

    const k2 = `${key}-2`;
    const both = await Promise.all([s.claim(k2, "alice", "create_invoice"), s.claim(k2, "alice", "create_invoice")]);
    assert.deepEqual(both.map((b) => b.kind).sort(), ["in_flight", "miss"]);
    await s.release(k2); // uncompleted → released
    assert.deepEqual(await s.claim(k2, "alice", "create_invoice"), { kind: "miss" });
  } finally {
    await s.close();
  }
});

test("postgres store: an unreachable database makes claim() throw (the caller refuses the write)", async () => {
  const s = new PostgresReceiptStore("postgresql://nobody:x@127.0.0.1:1/nope?connect_timeout=1");
  await assert.rejects(s.claim("k", "alice", "create_invoice"));
  await s.close();
});
