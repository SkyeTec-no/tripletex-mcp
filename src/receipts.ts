/**
 * Write receipts — the durable half of idempotency for the gated writes
 * (SkyeTec fork, plans/consolidation.md C3 in skyetec-tenant-substrate).
 *
 * The consuming tenant's committer sends `Idempotency-Key: <write_id>` on every
 * request and a retried approval reuses the same key. The committer's own outbox
 * short-circuits most retries, but the one window it cannot cover is "the write
 * landed, then the process died before the outbox was stamped" — there the row is
 * still `approved`, the human re-approves, the same key arrives again, and only
 * this store stands between that and a second invoice. It therefore has to
 * survive a restart of the wrapper, which the previous in-process Map did not.
 *
 * Shape copied from skyetec-io-backend's McpWriteReceiptDao (the reference
 * design): the row stores the whole result envelope so a replay is
 * byte-identical, and the key is bound to the caller AND the tool — the same
 * key from another caller or against another tool is misuse and is refused,
 * not replayed.
 *
 * One thing added beyond io: the key is CLAIMED before the write runs, not
 * recorded after. Two concurrent attempts with one key therefore cannot both
 * reach Tripletex, and an attempt that died between claiming and completing
 * leaves a visible, refusing row instead of an invisible double. For a money
 * write the honest failure is "check Tripletex before you retry", never
 * "probably fine".
 */
import pg from "pg";

export type ReceiptLookup =
  /** Nobody held the key; it is now ours and the write may run. */
  | { kind: "miss" }
  /** The same caller already completed this write; hand back its result. */
  | { kind: "replay"; result: unknown }
  /** The key is claimed by an attempt that has not completed (or died). */
  | { kind: "in_flight"; since: Date }
  /** The key exists under another caller or tool. */
  | { kind: "conflict" };

export interface ReceiptStore {
  readonly name: string;
  /** Atomically take the key for (scope, tool), or report why not. */
  claim(key: string, scope: string, tool: string): Promise<ReceiptLookup>;
  /** The write landed; store the result that every later replay must return. */
  complete(key: string, result: unknown): Promise<void>;
  /** The write did NOT land (error-shaped result, thrown error); free the key. */
  release(key: string): Promise<void>;
}

/** Lifetime of a receipt in the in-memory store. Bounds memory, nothing else. */
export const MEMORY_TTL_MS = 48 * 60 * 60 * 1000;

interface MemoryRow {
  scope: string;
  tool: string;
  at: number;
  result?: unknown;
  completed: boolean;
}

/**
 * The store used when no DSN is configured: single-process, lost on restart.
 * Keeps the previous behaviour for local/stdio use and for a wrapper that has
 * not been wired to Postgres yet — but it is announced at boot as NOT durable,
 * and the SkyeTec tenant wires the DSN in both environments.
 */
export class MemoryReceiptStore implements ReceiptStore {
  readonly name = "memory";
  private readonly rows = new Map<string, MemoryRow>();
  constructor(private readonly now: () => number = Date.now) {}

  async claim(key: string, scope: string, tool: string): Promise<ReceiptLookup> {
    const t = this.now();
    for (const [k, v] of this.rows) if (t - v.at > MEMORY_TTL_MS) this.rows.delete(k);
    const hit = this.rows.get(key);
    if (!hit) {
      this.rows.set(key, { scope, tool, at: t, completed: false });
      return { kind: "miss" };
    }
    if (hit.scope !== scope || hit.tool !== tool) return { kind: "conflict" };
    if (!hit.completed) return { kind: "in_flight", since: new Date(hit.at) };
    return { kind: "replay", result: hit.result };
  }

  async complete(key: string, result: unknown): Promise<void> {
    const row = this.rows.get(key);
    if (row) {
      row.result = result;
      row.completed = true;
    }
  }

  async release(key: string): Promise<void> {
    const row = this.rows.get(key);
    if (row && !row.completed) this.rows.delete(key);
  }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS write_receipts (
  idempotency_key text PRIMARY KEY,
  scope           text NOT NULL,
  tool            text NOT NULL,
  result_json     jsonb,
  created_utc     timestamptz NOT NULL DEFAULT now(),
  completed_utc   timestamptz
)`;

/**
 * Postgres-backed store. The table is created on first use (the role owns its
 * own database, same as the arrow wrapper), so no migration step exists outside
 * this file. Every method throws on a database failure; the caller in index.ts
 * turns a thrown claim() into a REFUSED write — a receipt store that cannot be
 * reached must never let an invoice through on hope.
 */
export class PostgresReceiptStore implements ReceiptStore {
  readonly name = "postgres";
  private readonly pool: pg.Pool;
  private ready: Promise<void> | undefined;

  constructor(dsn: string) {
    this.pool = new pg.Pool({ connectionString: dsn, max: 3 });
    // A pool emits 'error' for idle clients dropped by the server; without a
    // listener that is an uncaught exception that takes the process down.
    this.pool.on("error", (e: Error) => console.error(`receipts: idle client error: ${e.message}`));
  }

  /** Create the table if missing. Memoised; a failed attempt is retried next call. */
  ensureSchema(): Promise<void> {
    if (this.ready) return this.ready;
    const p: Promise<void> = this.pool.query(SCHEMA).then(
      () => undefined,
      (e: unknown) => {
        this.ready = undefined;
        throw e;
      }
    );
    this.ready = p;
    return p;
  }

  async claim(key: string, scope: string, tool: string): Promise<ReceiptLookup> {
    await this.ensureSchema();
    const ins = await this.pool.query(
      `INSERT INTO write_receipts (idempotency_key, scope, tool)
       VALUES ($1, $2, $3)
       ON CONFLICT (idempotency_key) DO NOTHING
       RETURNING 1`,
      [key, scope, tool]
    );
    if (ins.rowCount === 1) return { kind: "miss" };
    const row = await this.pool.query<{
      scope: string;
      tool: string;
      result_json: unknown;
      created_utc: Date;
      completed_utc: Date | null;
    }>(
      `SELECT scope, tool, result_json, created_utc, completed_utc
       FROM write_receipts WHERE idempotency_key = $1`,
      [key]
    );
    const r = row.rows[0];
    // Claimed and released between our INSERT and SELECT: treat as in flight
    // rather than racing again — the caller retries on its own schedule.
    if (!r) return { kind: "in_flight", since: new Date() };
    if (r.scope !== scope || r.tool !== tool) return { kind: "conflict" };
    if (r.completed_utc === null) return { kind: "in_flight", since: r.created_utc };
    return { kind: "replay", result: r.result_json };
  }

  async complete(key: string, result: unknown): Promise<void> {
    await this.pool.query(
      `UPDATE write_receipts SET result_json = $2::jsonb, completed_utc = now()
       WHERE idempotency_key = $1`,
      [key, JSON.stringify(result)]
    );
  }

  async release(key: string): Promise<void> {
    await this.pool.query(
      `DELETE FROM write_receipts WHERE idempotency_key = $1 AND completed_utc IS NULL`,
      [key]
    );
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/**
 * Pick the store from the environment. TRIPLETEX_MCP_STATE_DSN set → Postgres
 * (durable); unset → memory, announced on stderr when any write tool is enabled
 * so a non-durable deployment is never a quiet one.
 */
export function receiptStoreFromEnv(writesEnabled: boolean): ReceiptStore {
  const dsn = process.env.TRIPLETEX_MCP_STATE_DSN?.trim();
  if (dsn) return new PostgresReceiptStore(dsn);
  if (writesEnabled) {
    console.error(
      "receipts: TRIPLETEX_MCP_STATE_DSN unset — write dedupe is IN-MEMORY and does not survive a restart"
    );
  }
  return new MemoryReceiptStore();
}
