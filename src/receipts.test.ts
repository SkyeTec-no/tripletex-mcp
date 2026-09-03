import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryReceiptStore, MEMORY_TTL_MS } from "./receipts.js";

test("claim → complete → replay returns the stored result for the same caller and tool", async () => {
  const s = new MemoryReceiptStore();
  assert.deepEqual(await s.claim("k1", "alice", "create_invoice"), { kind: "miss" });
  await s.complete("k1", { content: [{ type: "text", text: "{\"id\":42}" }] });
  const again = await s.claim("k1", "alice", "create_invoice");
  assert.equal(again.kind, "replay");
  assert.deepEqual((again as { result: unknown }).result, { content: [{ type: "text", text: "{\"id\":42}" }] });
});

test("the same key from another caller or tool is a conflict, not a replay", async () => {
  const s = new MemoryReceiptStore();
  await s.claim("k1", "alice", "create_invoice");
  await s.complete("k1", "r");
  assert.deepEqual(await s.claim("k1", "bob", "create_invoice"), { kind: "conflict" });
  assert.deepEqual(await s.claim("k1", "alice", "create_time_entry"), { kind: "conflict" });
});

test("a claimed but uncompleted key is in flight — a second attempt cannot run", async () => {
  const s = new MemoryReceiptStore(() => 1000);
  await s.claim("k1", "alice", "create_invoice");
  const second = await s.claim("k1", "alice", "create_invoice");
  assert.equal(second.kind, "in_flight");
  assert.equal((second as { since: Date }).since.getTime(), 1000);
});

test("release frees a failed attempt so a retry can run; it never frees a completed one", async () => {
  const s = new MemoryReceiptStore();
  await s.claim("k1", "alice", "create_invoice");
  await s.release("k1");
  assert.deepEqual(await s.claim("k1", "alice", "create_invoice"), { kind: "miss" });
  await s.complete("k1", "r");
  await s.release("k1");
  assert.equal((await s.claim("k1", "alice", "create_invoice")).kind, "replay");
});

test("memory receipts expire after the TTL", async () => {
  let now = 0;
  const s = new MemoryReceiptStore(() => now);
  await s.claim("k1", "alice", "create_invoice");
  await s.complete("k1", "r");
  now = MEMORY_TTL_MS + 1;
  assert.deepEqual(await s.claim("k1", "alice", "create_invoice"), { kind: "miss" });
});
