#!/usr/bin/env node
/**
 * Tripletex MCP Server — thin proxy over Tripletex API v2 (see docs/PRD-Tripletex-MCP-Rebuild.md).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { AsyncLocalStorage } from "node:async_hooks";
import {
  TripletexApiError,
  TripletexClient,
  type TripletexCredentials,
} from "./tripletex-client.js";
import {
  buildOrderBody,
  transformVoucherPosting,
  type OrderLineInput,
} from "./tripletex-transform.js";
import { registerSkills } from "./skills/registry.js";
import { handleOAuth, send401, tripletexTokenFromBearer } from "./oauth.js";

/**
 * The read-only surface (SkyeTec fork): with MCP_READ_ONLY=true only these
 * tools register and the workflow skills stay off — writes to Tripletex belong
 * to the orchestrator, never to this connector (tenant ADR-0022).
 */
const READ_TOOLS = new Set([
  "get_invoice",
  "search_invoices",
  "search_supplier_invoices",
  "search_orders",
  "search_customers",
  "search_products",
  "search_suppliers",
  "search_accounts",
  "search_vat_types",
  "search_vouchers",
  "get_voucher",
  "get_balance_sheet",
  "search_projects",
  "search_activities",
  "search_time_entries",
  "search_employees",
  "whoami",
]);

function readOnly(): boolean {
  return process.env.MCP_READ_ONLY === "true";
}

/**
 * Idempotency for the gated writes (SkyeTec fork). The consuming tenant's
 * committer sends `Idempotency-Key: <write_id>` on every HTTP request of its
 * one-shot MCP client; a retried approval reuses the same key. The key rides
 * AsyncLocalStorage from the HTTP handler into the tool callback (the callback
 * closes over the session, not the request), and a keyed write returns the
 * cached FIRST result instead of running again — an invoice is money, and a
 * committer retry must never create it twice. In-memory only (min_replicas=1;
 * a restart loses the cache, but the tenant outbox's status short-circuit is
 * the first ring of dedupe — this is the belt to that braces).
 */
const idemContext = new AsyncLocalStorage<{ key: string | undefined }>();
const IDEM_TTL_MS = 48 * 60 * 60 * 1000;
const idemCache = new Map<string, { at: number; result: unknown }>();

function isErrorShapedResult(result: unknown): boolean {
  const text = (result as { content?: Array<{ text?: string }> } | null)?.content?.[0]?.text;
  if (!text) return false;
  try {
    const parsed = JSON.parse(text) as { httpStatus?: number };
    return typeof parsed.httpStatus === "number" && parsed.httpStatus >= 400;
  } catch {
    return false;
  }
}

function idempotencyKeyFromRequest(req: IncomingMessage): string | undefined {
  const raw = req.headers["idempotency-key"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value && value.trim() ? value.trim() : undefined;
}

function withIdempotency(
  toolName: string,
  cb: (...a: unknown[]) => unknown
): (...a: unknown[]) => Promise<unknown> {
  return async (...a: unknown[]) => {
    const key = idemContext.getStore()?.key;
    if (!key) return cb(...a);
    const cacheKey = `${toolName}:${key}`;
    const now = Date.now();
    for (const [k, v] of idemCache) if (now - v.at > IDEM_TTL_MS) idemCache.delete(k);
    const hit = idemCache.get(cacheKey);
    if (hit) return hit.result;
    const result = await cb(...a);
    // Cache only success — a failed attempt must stay retryable. Upstream's run()
    // returns Tripletex API errors as SUCCESS text ({"httpStatus": 4xx, ...}), so
    // error-shaped text must be recognised here or a failed invoice would be
    // "deduped" into permanent failure.
    if (!(result as { isError?: boolean } | null)?.isError && !isErrorShapedResult(result)) {
      idemCache.set(cacheKey, { at: now, result });
    }
    return result;
  };
}

/**
 * Writes explicitly opened through the read-only gate (SkyeTec fork):
 * MCP_WRITE_TOOLS is a comma-separated allowlist of write-tool names to register
 * IN ADDITION to the read surface. Empty/unset → pure read-only. The consuming
 * tenant gates every one of these behind its human-approval pipe; this knob only
 * decides what exists to be gated.
 */
function allowedWriteTools(): Set<string> {
  return new Set(
    (process.env.MCP_WRITE_TOOLS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

/**
 * A view of the server that drops write tools when MCP_READ_ONLY is on — and
 * stamps the surviving reads with readOnlyHint, so clients that trust the
 * server's own annotations (the SkyeTec tenant's baseline tests do) see the
 * guarantee the mode enforces.
 */
function toolSink(server: McpServer): McpServer {
  if (!readOnly()) return server;
  const writes = allowedWriteTools();
  return new Proxy(server, {
    get(target, prop, receiver) {
      if (prop === "tool") {
        return (name: string, ...rest: unknown[]) => {
          const isRead = READ_TOOLS.has(name);
          if (!isRead && !writes.has(name)) return undefined;
          const cb = rest.pop() as (...a: unknown[]) => unknown;
          return (target.tool as (...a: unknown[]) => unknown)(
            name,
            ...rest,
            isRead
              ? { readOnlyHint: true, destructiveHint: false, openWorldHint: true }
              : { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
            isRead ? cb : withIdempotency(name, cb)
          );
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

/**
 * Client whose construction is deferred to the first tool call, so the HTTP
 * server starts and passes healthchecks even before credentials are configured
 * — and so a session that supplies no credentials fails on use, not on connect.
 */
function lazyClient(credentials?: TripletexCredentials): TripletexClient {
  let real: TripletexClient | null = null;
  return new Proxy({} as TripletexClient, {
    get(_target, prop) {
      if (!real) real = new TripletexClient(credentials);
      const value = (real as any)[prop];
      // Bind methods to the REAL instance: called through the proxy, `this`
      // would otherwise be the proxy, whose default `set` writes onto the empty
      // target — `this.session = …` then never lands on the client and every
      // call dies on a null session.
      return typeof value === "function" ? value.bind(real) : value;
    },
  });
}

/**
 * Per-request credentials for the HTTP transport. Lets one deployment serve
 * several companies, and keeps the endpoint URL alone from being enough to read
 * the accounts. Returns undefined when no usable header is present, in which
 * case the client falls back to the environment.
 */
function credentialsFromHeaders(
  req: IncomingMessage
): TripletexCredentials | undefined {
  const pick = (name: string) => {
    const raw = req.headers[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    return value && value.trim() ? value.trim() : undefined;
  };
  const credentials: TripletexCredentials = {
    jwt: pick("x-tripletex-jwt"),
    consumerToken: pick("x-tripletex-consumer-token"),
    employeeToken: pick("x-tripletex-employee-token"),
    env: pick("x-tripletex-env"),
  };
  return credentials.jwt || credentials.employeeToken
    ? credentials
    : undefined;
}

const server = new McpServer({
  name: "tripletex",
  version: "2.0.0",
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatResult(data: unknown): string {
  return JSON.stringify(data, null, 2);
}

function formatTripletexError(e: TripletexApiError): string {
  let parsed: unknown = e.bodyText;
  try {
    parsed = JSON.parse(e.bodyText) as unknown;
  } catch {
    /* keep raw string */
  }
  return JSON.stringify(
    { httpStatus: e.status, tripletexResponse: parsed },
    null,
    2
  );
}

async function run<T>(fn: () => Promise<T>) {
  try {
    const data = await fn();
    return { content: [{ type: "text" as const, text: formatResult(data) }] };
  } catch (e) {
    if (e instanceof TripletexApiError) {
      return {
        content: [{ type: "text" as const, text: formatTripletexError(e) }],
      };
    }
    throw e;
  }
}

function optionalParams(
  obj: Record<string, string | number | boolean | undefined | null>
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || v === "") continue;
    out[k] = typeof v === "boolean" ? String(v) : String(v);
  }
  return out;
}

/** Tripletex invoice/order list responses often use `value.id`. */
function readValueId(data: unknown): number | undefined {
  if (data && typeof data === "object" && "value" in data) {
    const v = (data as { value?: { id?: number } }).value;
    return v?.id;
  }
  return undefined;
}

const postalAddressSchema = z
  .object({
    addressLine1: z.string().optional(),
    postalCode: z.string().optional(),
    city: z.string().optional(),
    country: z.object({ id: z.number() }).optional(),
  })
  .optional();

const orderLineSchema: z.ZodType<OrderLineInput> = z.object({
  description: z.string().optional(),
  count: z.number().optional(),
  unitPriceExcludingVatCurrency: z.number().optional(),
  unitPriceIncludingVatCurrency: z.number().optional(),
  vatTypeId: z.number().optional(),
  productId: z.number().optional(),
  discount: z.number().optional(),
});

// ===========================================================================
// Tool registration function (used per-session for HTTP transport)
// ===========================================================================

function registerAllTools(server: McpServer, client: TripletexClient) {

// ===========================================================================
// INVOICES & ORDERS
// ===========================================================================

server.tool(
  "create_order",
  "Create an order in Tripletex. Use invoice_order to convert to invoice. Order line fields match Tripletex (count, unitPriceExcludingVatCurrency or unitPriceIncludingVatCurrency per isPrioritizeAmountsIncludingVat).",
  {
    customerId: z.number().describe("Customer ID → customer.id"),
    orderDate: z.string().describe("YYYY-MM-DD"),
    deliveryDate: z.string().describe("YYYY-MM-DD"),
    orderLines: z.array(orderLineSchema).optional(),
    isPrioritizeAmountsIncludingVat: z.boolean().optional(),
    currencyId: z.number().optional(),
    ourReference: z.string().optional(),
    yourReference: z.string().optional(),
    invoiceComment: z.string().optional(),
    receiverEmail: z.string().optional(),
    invoicesDueIn: z.number().optional(),
  },
  async (args) =>
    run(() => client.post("/order", buildOrderBody(args)))
);

server.tool(
  "invoice_order",
  "Convert an order to an invoice. Omit sendToCustomer to use Tripletex default (typically send).",
  {
    orderId: z.number(),
    invoiceDate: z.string().describe("YYYY-MM-DD"),
    sendToCustomer: z.boolean().optional(),
  },
  async ({ orderId, invoiceDate, sendToCustomer }) =>
    run(() => {
      const params = optionalParams({
        invoiceDate,
        ...(sendToCustomer !== undefined ? { sendToCustomer } : {}),
      });
      return client.put(`/order/${orderId}/:invoice`, {}, params);
    })
);

server.tool(
  "create_invoice",
  "Create order then invoice in one flow. orderLines use Tripletex field names (count, unitPriceExcludingVatCurrency, etc.).",
  {
    customerId: z.number(),
    invoiceDate: z.string().describe("YYYY-MM-DD"),
    orderLines: z.array(orderLineSchema),
    isPrioritizeAmountsIncludingVat: z.boolean().optional(),
    currencyId: z.number().optional(),
    ourReference: z.string().optional(),
    invoiceComment: z.string().optional(),
    sendToCustomer: z.boolean().optional(),
  },
  async (args) =>
    run(async () => {
      const orderBody = buildOrderBody({
        customerId: args.customerId,
        orderDate: args.invoiceDate,
        deliveryDate: args.invoiceDate,
        orderLines: args.orderLines,
        isPrioritizeAmountsIncludingVat: args.isPrioritizeAmountsIncludingVat,
        currencyId: args.currencyId,
        ourReference: args.ourReference,
        invoiceComment: args.invoiceComment,
      });
      const orderResult = await client.post("/order", orderBody);
      const orderId = readValueId(orderResult);
      if (orderId === undefined) {
        throw new Error(
          "create_invoice: order created but no value.id in response:\n" +
            formatResult(orderResult)
        );
      }
      const params = optionalParams({
        invoiceDate: args.invoiceDate,
        ...(args.sendToCustomer !== undefined
          ? { sendToCustomer: args.sendToCustomer }
          : {}),
      });
      return client.put(`/order/${orderId}/:invoice`, {}, params);
    })
);

server.tool(
  "get_invoice",
  "Get invoice by ID. Optional fields for Tripletex expansion e.g. *,orders(*),orderLines(*)",
  {
    id: z.number(),
    fields: z.string().optional(),
  },
  async ({ id, fields }) =>
    run(() => {
      const params = optionalParams({ fields });
      return client.get(`/invoice/${id}`, params);
    })
);

server.tool(
  "search_invoices",
  "Search outgoing invoices by date range (required) and optional filters.",
  {
    invoiceDateFrom: z.string().describe("YYYY-MM-DD"),
    invoiceDateTo: z.string().describe("YYYY-MM-DD"),
    customerId: z.number().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    isCredited: z.boolean().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        invoiceDateFrom: args.invoiceDateFrom,
        invoiceDateTo: args.invoiceDateTo,
        customerId: args.customerId,
        fields: args.fields,
        isCredited: args.isCredited,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/invoice", params);
    })
);

server.tool(
  "search_supplier_invoices",
  "Search incoming supplier invoices (required date range).",
  {
    invoiceDateFrom: z.string().describe("YYYY-MM-DD"),
    invoiceDateTo: z.string().describe("YYYY-MM-DD"),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    supplierId: z.number().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        invoiceDateFrom: args.invoiceDateFrom,
        invoiceDateTo: args.invoiceDateTo,
        fields: args.fields,
        supplierId: args.supplierId,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/supplierInvoice", params);
    })
);

server.tool(
  "search_orders",
  "Search orders by order date range. Use isClosed=false for open (not yet invoiced) orders.",
  {
    orderDateFrom: z.string().describe("YYYY-MM-DD"),
    orderDateTo: z.string().describe("YYYY-MM-DD"),
    customerId: z.number().optional(),
    isClosed: z.boolean().optional(),
    isSubscription: z.boolean().optional(),
    number: z.string().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        orderDateFrom: args.orderDateFrom,
        orderDateTo: args.orderDateTo,
        customerId: args.customerId,
        isClosed: args.isClosed,
        isSubscription: args.isSubscription,
        number: args.number,
        fields: args.fields,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/order", params);
    })
);

// ===========================================================================
// CUSTOMERS & SUPPLIERS & PRODUCTS
// ===========================================================================

server.tool(
  "search_customers",
  "Search customers (query maps to Tripletex name filter).",
  {
    query: z.string().optional(),
    customerNumber: z.string().optional(),
    email: z.string().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    isActive: z.boolean().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        name: args.query,
        customerNumber: args.customerNumber,
        email: args.email,
        fields: args.fields,
        isActive: args.isActive,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/customer", params);
    })
);

const createCustomerSchema = z.object({
  name: z.string(),
  organizationNumber: z.string().optional(),
  email: z.string().optional(),
  invoiceEmail: z.string().optional(),
  phoneNumber: z.string().optional(),
  phoneNumberMobile: z.string().optional(),
  invoiceSendMethod: z.string().optional(),
  language: z.string().optional(),
  currencyId: z.number().optional(),
  postalAddress: postalAddressSchema,
});

function buildCustomerBody(
  input: z.infer<typeof createCustomerSchema>
): Record<string, unknown> {
  const body: Record<string, unknown> = { name: input.name };
  if (input.organizationNumber !== undefined)
    body.organizationNumber = input.organizationNumber;
  if (input.email !== undefined) body.email = input.email;
  if (input.invoiceEmail !== undefined) body.invoiceEmail = input.invoiceEmail;
  if (input.phoneNumber !== undefined) body.phoneNumber = input.phoneNumber;
  if (input.phoneNumberMobile !== undefined)
    body.phoneNumberMobile = input.phoneNumberMobile;
  if (input.invoiceSendMethod !== undefined)
    body.invoiceSendMethod = input.invoiceSendMethod;
  if (input.language !== undefined) body.language = input.language;
  if (input.currencyId !== undefined)
    body.currency = { id: input.currencyId };
  if (input.postalAddress !== undefined)
    body.postalAddress = input.postalAddress;
  return body;
}

server.tool(
  "create_customer",
  "Create customer. currencyId → currency.id",
  createCustomerSchema.shape,
  async (input) =>
    run(() =>
      client.post("/customer", buildCustomerBody(createCustomerSchema.parse(input)))
    )
);

server.tool(
  "update_customer",
  "Update customer by id (same optional fields as create).",
  {
    id: z.number(),
    name: z.string().optional(),
    organizationNumber: z.string().optional(),
    email: z.string().optional(),
    invoiceEmail: z.string().optional(),
    phoneNumber: z.string().optional(),
    phoneNumberMobile: z.string().optional(),
    invoiceSendMethod: z.string().optional(),
    language: z.string().optional(),
    currencyId: z.number().optional(),
    postalAddress: postalAddressSchema,
  },
  async ({ id, ...rest }) =>
    run(() => {
      const body: Record<string, unknown> = {};
      if (rest.name !== undefined) body.name = rest.name;
      if (rest.organizationNumber !== undefined)
        body.organizationNumber = rest.organizationNumber;
      if (rest.email !== undefined) body.email = rest.email;
      if (rest.invoiceEmail !== undefined) body.invoiceEmail = rest.invoiceEmail;
      if (rest.phoneNumber !== undefined) body.phoneNumber = rest.phoneNumber;
      if (rest.phoneNumberMobile !== undefined)
        body.phoneNumberMobile = rest.phoneNumberMobile;
      if (rest.invoiceSendMethod !== undefined)
        body.invoiceSendMethod = rest.invoiceSendMethod;
      if (rest.language !== undefined) body.language = rest.language;
      if (rest.currencyId !== undefined) body.currency = { id: rest.currencyId };
      if (rest.postalAddress !== undefined)
        body.postalAddress = rest.postalAddress;
      return client.put(`/customer/${id}`, body);
    })
);

server.tool(
  "search_products",
  "Search products (query → name filter).",
  {
    query: z.string().optional(),
    number: z.string().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    isInactive: z.boolean().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        name: args.query,
        number: args.number,
        fields: args.fields,
        isInactive: args.isInactive,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/product", params);
    })
);

server.tool(
  "create_product",
  "Create product. vatTypeId / currencyId expanded to nested ids.",
  {
    name: z.string(),
    number: z.string().optional(),
    priceExcludingVatCurrency: z.number().optional(),
    priceIncludingVatCurrency: z.number().optional(),
    vatTypeId: z.number().optional(),
    currencyId: z.number().optional(),
    description: z.string().optional(),
    isInactive: z.boolean().optional(),
  },
  async (args) =>
    run(() => {
      const body: Record<string, unknown> = { name: args.name };
      if (args.number !== undefined) body.number = args.number;
      if (args.priceExcludingVatCurrency !== undefined)
        body.priceExcludingVatCurrency = args.priceExcludingVatCurrency;
      if (args.priceIncludingVatCurrency !== undefined)
        body.priceIncludingVatCurrency = args.priceIncludingVatCurrency;
      if (args.vatTypeId !== undefined) body.vatType = { id: args.vatTypeId };
      if (args.currencyId !== undefined) body.currency = { id: args.currencyId };
      if (args.description !== undefined) body.description = args.description;
      if (args.isInactive !== undefined) body.isInactive = args.isInactive;
      return client.post("/product", body);
    })
);

server.tool(
  "search_suppliers",
  "Search suppliers (query → name).",
  {
    query: z.string().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    organizationNumber: z.string().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        name: args.query,
        fields: args.fields,
        organizationNumber: args.organizationNumber,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/supplier", params);
    })
);

server.tool(
  "create_supplier",
  "Create supplier. Optional bankAccountNumber (Tripletex field name).",
  {
    name: z.string(),
    organizationNumber: z.string().optional(),
    email: z.string().optional(),
    postalAddress: postalAddressSchema,
    bankAccountNumber: z.string().optional(),
  },
  async (args) =>
    run(() => {
      const body: Record<string, unknown> = { name: args.name };
      if (args.organizationNumber !== undefined)
        body.organizationNumber = args.organizationNumber;
      if (args.email !== undefined) body.email = args.email;
      if (args.postalAddress !== undefined)
        body.postalAddress = args.postalAddress;
      if (args.bankAccountNumber !== undefined)
        body.bankAccountNumber = args.bankAccountNumber;
      return client.post("/supplier", body);
    })
);

// ===========================================================================
// LEDGER
// ===========================================================================

server.tool(
  "search_accounts",
  "Search chart of accounts (query → name; optional numberFrom/numberTo).",
  {
    query: z.string().optional(),
    numberFrom: z.string().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    numberTo: z.string().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        name: args.query,
        numberFrom: args.numberFrom,
        fields: args.fields,
        numberTo: args.numberTo,
        from: args.from,
        count: args.count ?? 50,
      });
      return client.get("/ledger/account", params);
    })
);

server.tool(
  "search_vat_types",
  "List VAT types (query → name filter if supported by API).",
  {
    query: z.string().optional(),
  },
  async ({ query }) =>
    run(() => {
      const params = optionalParams({ name: query });
      return client.get("/ledger/vatType", params);
    })
);

server.tool(
  "create_voucher",
  "Create accounting voucher. Each posting needs accountId, amountGross, date (Tripletex posting DTO).",
  {
    date: z.string().describe("Voucher date YYYY-MM-DD"),
    description: z.string().optional(),
    postings: z.array(
      z.object({
        accountId: z.number(),
        amountGross: z.number(),
        amountGrossCurrency: z.number().optional(),
        date: z.string().describe("Posting date YYYY-MM-DD"),
        vatTypeId: z.number().optional(),
        row: z.number().optional(),
      })
    ),
  },
  async ({ date, description, postings }) =>
    run(() =>
      client.post("/ledger/voucher", {
        date,
        ...(description !== undefined ? { description } : {}),
        postings: postings.map(transformVoucherPosting),
      })
    )
);

server.tool(
  "search_vouchers",
  "Search vouchers by date range.",
  {
    dateFrom: z.string(),
    dateTo: z.string(),
    numberFrom: z.string().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    numberTo: z.string().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        dateFrom: args.dateFrom,
        dateTo: args.dateTo,
        numberFrom: args.numberFrom,
        fields: args.fields,
        numberTo: args.numberTo,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/ledger/voucher", params);
    })
);

server.tool(
  "get_voucher",
  "Get voucher by ID; optional fields for expansion.",
  {
    id: z.number(),
    fields: z.string().optional(),
  },
  async ({ id, fields }) =>
    run(() => {
      const params = optionalParams({ fields });
      return client.get(`/ledger/voucher/${id}`, params);
    })
);

// ===========================================================================
// BALANCE SHEET
// ===========================================================================

server.tool(
  "get_balance_sheet",
  "Balance sheet for period; optional account range and filters per Tripletex API.",
  {
    dateFrom: z.string(),
    dateTo: z.string(),
    accountNumberFrom: z.number().optional(),
    accountNumberTo: z.number().optional(),
    customerId: z.number().optional(),
    employeeId: z.number().optional(),
    departmentId: z.number().optional(),
    projectId: z.number().optional(),
    includeSubProjects: z.boolean().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    activeAccountsWithoutMovements: z.boolean().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        dateFrom: args.dateFrom,
        dateTo: args.dateTo,
        accountNumberFrom: args.accountNumberFrom,
        accountNumberTo: args.accountNumberTo,
        customerId: args.customerId,
        employeeId: args.employeeId,
        departmentId: args.departmentId,
        projectId: args.projectId,
        includeSubProjects: args.includeSubProjects,
        fields: args.fields,
        activeAccountsWithoutMovements: args.activeAccountsWithoutMovements,
        from: args.from,
        count: args.count ?? 1000,
      });
      return client.get("/balanceSheet", params);
    })
);

// ===========================================================================
// TIME & EMPLOYEES
// ===========================================================================

server.tool(
  "search_projects",
  "Search projects (query → name). Supports Tripletex filters (isClosed, customerId, projectManagerId, number) and fields expansion.",
  {
    query: z.string().optional(),
    number: z.string().optional(),
    isClosed: z.boolean().optional(),
    isOffer: z.boolean().optional(),
    customerId: z.number().optional(),
    projectManagerId: z.number().optional(),
    departmentId: z.number().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        name: args.query,
        number: args.number,
        isClosed: args.isClosed,
        isOffer: args.isOffer,
        customerId: args.customerId,
        projectManagerId: args.projectManagerId,
        departmentId: args.departmentId,
        fields: args.fields,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/project", params);
    })
);

server.tool(
  "search_activities",
  "Search activities (query → name).",
  {
    query: z.string().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async ({ query, fields, from, count }) =>
    run(() => {
      const params = optionalParams({
        name: query,
        fields,
        from,
        count: count ?? 50,
      });
      return client.get("/activity", params);
    })
);

server.tool(
  "search_time_entries",
  "Search timesheet entries in date range.",
  {
    dateFrom: z.string(),
    dateTo: z.string(),
    employeeId: z.number().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    projectId: z.number().optional(),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        dateFrom: args.dateFrom,
        dateTo: args.dateTo,
        employeeId: args.employeeId,
        fields: args.fields,
        projectId: args.projectId,
        from: args.from,
        count: args.count ?? 50,
      });
      return client.get("/timesheet/entry", params);
    })
);

server.tool(
  "create_time_entry",
  "Log hours. employeeId required per PRD (explicit employee).",
  {
    employeeId: z.number(),
    projectId: z.number(),
    activityId: z.number(),
    date: z.string(),
    hours: z.number(),
    comment: z.string().optional(),
  },
  async ({ employeeId, projectId, activityId, date, hours, comment }) =>
    run(() => {
      const body: Record<string, unknown> = {
        employee: { id: employeeId },
        project: { id: projectId },
        activity: { id: activityId },
        date,
        hours,
      };
      if (comment !== undefined) body.comment = comment;
      return client.post("/timesheet/entry", body);
    })
);

server.tool(
  "search_employees",
  "Search employees; query is sent as firstName filter (see Tripletex /employee OpenAPI for more filters).",
  {
    query: z.string().optional(),
    lastName: z.string().optional(),
    employeeNumber: z.string().optional(),
    departmentId: z.number().optional(),
    fields: z.string().optional().describe("Tripletex `fields` expansion, e.g. \"id,name,customer(id,name)\" or \"*\""),
    from: z.number().optional(),
    count: z.number().optional(),
  },
  async (args) =>
    run(() => {
      const params = optionalParams({
        firstName: args.query,
        lastName: args.lastName,
        employeeNumber: args.employeeNumber,
        departmentId: args.departmentId,
        fields: args.fields,
        from: args.from,
        count: args.count ?? 25,
      });
      return client.get("/employee", params);
    })
);

server.tool(
  "create_employee",
  "Create a new employee. Requires department. Start date goes on /employee/employment, not here.",
  {
    firstName: z.string(),
    lastName: z.string(),
    departmentId: z.number().describe("Department ID"),
    userType: z.string().optional().describe("e.g. STANDARD (default)"),
    email: z.string().optional(),
    phoneNumberMobile: z.string().optional(),
    dateOfBirth: z.string().optional().describe("YYYY-MM-DD"),
  },
  async (args) =>
    run(() => {
      const body: Record<string, unknown> = {
        firstName: args.firstName,
        lastName: args.lastName,
        department: { id: args.departmentId },
        userType: args.userType ?? "STANDARD",
      };
      if (args.email !== undefined) body.email = args.email;
      if (args.phoneNumberMobile !== undefined)
        body.phoneNumberMobile = args.phoneNumberMobile;
      if (args.dateOfBirth !== undefined) body.dateOfBirth = args.dateOfBirth;
      return client.post("/employee", body);
    })
);

server.tool(
  "create_project",
  "Create a new project for time tracking and invoicing.",
  {
    name: z.string().describe("Project name"),
    number: z.string().optional().describe("Project number"),
    projectManagerId: z.number().optional().describe("Employee ID of project manager"),
    customerId: z.number().optional().describe("Customer ID to link"),
    startDate: z.string().optional().describe("YYYY-MM-DD"),
    endDate: z.string().optional().describe("YYYY-MM-DD"),
  },
  async (args) =>
    run(() => {
      const body: Record<string, unknown> = { name: args.name };
      if (args.number !== undefined) body.number = args.number;
      if (args.projectManagerId !== undefined)
        body.projectManager = { id: args.projectManagerId };
      if (args.customerId !== undefined)
        body.customer = { id: args.customerId };
      if (args.startDate !== undefined) body.startDate = args.startDate;
      if (args.endDate !== undefined) body.endDate = args.endDate;
      return client.post("/project", body);
    })
);

server.tool(
  "create_department",
  "Create a new department (avdeling/kostnadssted).",
  {
    name: z.string().describe("Department name"),
    departmentNumber: z.string().optional().describe("Unique department number"),
    departmentManagerId: z.number().optional().describe("Employee ID of department manager"),
  },
  async (args) =>
    run(() => {
      const body: Record<string, unknown> = { name: args.name };
      if (args.departmentNumber !== undefined)
        body.departmentNumber = args.departmentNumber;
      if (args.departmentManagerId !== undefined)
        body.departmentManager = { id: args.departmentManagerId };
      return client.post("/department", body);
    })
);

// ===========================================================================
// UTILITY
// ===========================================================================

server.tool(
  "whoami",
  "Authenticated session / company info.",
  {},
  async () => run(() => client.get("/token/session/>whoAmI"))
);

} // end registerAllTools

// ===========================================================================
// SKILLS (MCP Prompts + Resource)
// ===========================================================================

// ===========================================================================
// START
// ===========================================================================

async function main() {
  const transportMode = process.env.MCP_TRANSPORT ?? "stdio";

  if (transportMode === "http") {
    // --- Streamable HTTP transport (for Railway / remote hosting) ---
    const PORT = parseInt(process.env.PORT ?? "3000", 10);

    // Track active transports by session ID
    const transports = new Map<string, StreamableHTTPServerTransport>();

    const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

      // Health check endpoint for Railway
      if (url.pathname === "/health" || url.pathname === "/") {
        if (req.method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ status: "ok", server: "tripletex-mcp", version: "2.0.0" }));
          return;
        }
      }

      // OAuth authorization-server endpoints (SkyeTec fork) — discovery, DCR,
      // the paste-token authorize page, and token minting. No-ops unless
      // OAUTH_ENC_KEY is configured.
      if (await handleOAuth(req, res, url)) return;

      // MCP endpoint
      if (url.pathname === "/mcp") {
        // With OAuth enabled the Bearer token is the ONLY accepted credential —
        // the legacy X-Tripletex-* headers would bypass the allowlist and the
        // token sealing, so they are ignored entirely in that mode.
        const bearer = tripletexTokenFromBearer(req);
        if (bearer === null) {
          send401(res);
          return;
        }

        // Handle new session initialization (POST without session ID)
        if (req.method === "POST") {
          const sessionId = req.headers["mcp-session-id"] as string | undefined;

          if (sessionId && transports.has(sessionId)) {
            // Existing session — forward to its transport
            const transport = transports.get(sessionId)!;
            await idemContext.run({ key: idempotencyKeyFromRequest(req) }, () => transport.handleRequest(req, res));
            return;
          }

          // New session — create a new transport and connect a new server instance
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => crypto.randomUUID(),
            onsessioninitialized: (id) => {
              transports.set(id, transport);
              console.error(`Session initialized: ${id}`);
            },
          });

          transport.onclose = () => {
            const sid = [...transports.entries()].find(([, t]) => t === transport)?.[0];
            if (sid) {
              transports.delete(sid);
              console.error(`Session closed: ${sid}`);
            }
          };

          // Each session gets its own McpServer instance so sessions are isolated
          const sessionServer = new McpServer({
            name: "tripletex",
            version: "2.0.0",
          });

          // Re-register all tools on the session server, bound to whatever
          // credentials this client sent (falling back to the environment).
          const credentials =
            bearer === "off"
              ? credentialsFromHeaders(req)
              : { jwt: bearer, env: process.env.TRIPLETEX_ENV };
          registerAllTools(toolSink(sessionServer), lazyClient(credentials));
          if (!readOnly()) registerSkills(sessionServer);

          await sessionServer.connect(transport);
          await idemContext.run({ key: idempotencyKeyFromRequest(req) }, () => transport.handleRequest(req, res));
          return;
        }

        // Handle GET for SSE stream (long-lived connection)
        if (req.method === "GET") {
          const sessionId = req.headers["mcp-session-id"] as string | undefined;
          if (sessionId && transports.has(sessionId)) {
            const transport = transports.get(sessionId)!;
            await idemContext.run({ key: idempotencyKeyFromRequest(req) }, () => transport.handleRequest(req, res));
            return;
          }
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing or invalid session ID" }));
          return;
        }

        // Handle DELETE for session cleanup
        if (req.method === "DELETE") {
          const sessionId = req.headers["mcp-session-id"] as string | undefined;
          if (sessionId && transports.has(sessionId)) {
            const transport = transports.get(sessionId)!;
            await idemContext.run({ key: idempotencyKeyFromRequest(req) }, () => transport.handleRequest(req, res));
            transports.delete(sessionId);
            return;
          }
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing or invalid session ID" }));
          return;
        }

        res.writeHead(405, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Method not allowed" }));
        return;
      }

      // 404 for everything else
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    });

    httpServer.listen(PORT, () => {
      console.error(`Tripletex MCP server running on http://0.0.0.0:${PORT}/mcp`);
    });
  } else {
    // --- stdio transport (default, for local usage) ---
    registerAllTools(toolSink(server), lazyClient());
    if (!readOnly()) registerSkills(server);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Tripletex MCP server running on stdio");
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
