/**
 * OAuth 2.1 authorization-server facade for hosted MCP clients (SkyeTec fork).
 *
 * Why this exists: MCP clients like the SkyeTec substrate speak the MCP auth spec —
 * RFC 8414 discovery, RFC 7591 dynamic client registration, authorization-code +
 * PKCE, refresh tokens, Bearer on every call. Tripletex's own hosted MCP refuses
 * to register clients with a server-side redirect URI ("not on the allowlist"),
 * which is what pushed this wrapper into existence; this module is the half the
 * upstream project lacked.
 *
 * The design is STATELESS on purpose — no database, no session store:
 *
 *   - "Logging in" at /authorize means pasting a personal Tripletex API token
 *     (the tlxr_ refresh JWT from Selskap → API-tokens). It is validated by
 *     actually creating a Tripletex session with it, then sealed (AES-256-GCM,
 *     OAUTH_ENC_KEY) inside the authorization code, and later inside the access
 *     and refresh tokens this server mints. Restarts lose nothing; every minted
 *     token stands alone. Per-user scoping is Tripletex's: the sealed token
 *     carries exactly the permissions of the user who created it.
 *   - client_id is likewise a sealed blob of the client's registered redirect
 *     URIs, so /register needs no storage either. Registration succeeds only for
 *     redirect URIs on OAUTH_ALLOWED_REDIRECTS (comma-separated, exact match)
 *     or loopback (127.0.0.1 / localhost, any port) — the same policy Tripletex
 *     enforces, with our own deployments allowlisted.
 *
 * PKCE (S256) is required. Tokens expire; the refresh token's practical ceiling
 * is the sealed Tripletex token's own expiry — when the tlxr dies, refresh
 * yields 401 with invalid_grant and the user reconnects.
 */

import { createHash, createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

const PROD_BASE = "https://tripletex.no/v2";
const TEST_BASE = "https://api-test.tripletex.tech/v2";

const apiBase = (env: string) => (env === "test" ? TEST_BASE : PROD_BASE);

/** The application name users must type when creating their key in Tripletex. */
const consumerName = () => process.env.TRIPLETEX_CONSUMER_NAME ?? "";

const CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TTL_MS = 24 * 60 * 60 * 1000;
const REFRESH_TTL_MS = 180 * 24 * 60 * 60 * 1000;

export function oauthEnabled(): boolean {
  return Boolean(process.env.OAUTH_ENC_KEY);
}

function encKey(): Buffer {
  const raw = process.env.OAUTH_ENC_KEY ?? "";
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error("OAUTH_ENC_KEY must be 32 bytes, base64-encoded");
  }
  return key;
}

function publicBaseUrl(): string {
  const url = process.env.PUBLIC_BASE_URL;
  if (!url) throw new Error("PUBLIC_BASE_URL is required when OAuth is enabled");
  return url.replace(/\/$/, "");
}

// The RESOURCE base may differ from the AS base: behind the mcp.skyetec.ai
// path router this server is mounted at /<connector> while the OAuth AS stays
// at the origin root (the substrate's silent refresh is origin-root-only, so
// the issuer cannot move under the path). Unset → same as PUBLIC_BASE_URL,
// which is the standalone-hostname deployment.
function publicResourceUrl(): string {
  const url = process.env.PUBLIC_RESOURCE_URL;
  return url ? url.replace(/\/$/, "") : publicBaseUrl();
}

// RFC 9728 canonical form: well-known at the origin root with the resource
// path appended. Standalone (resource == base) keeps the historic un-suffixed
// URL so existing clients see no change.
function resourceMetadataUrl(): string {
  const base = publicBaseUrl();
  const resource = publicResourceUrl();
  if (resource === base) return `${base}/.well-known/oauth-protected-resource`;
  const path = resource.startsWith(base) ? resource.slice(base.length) : "";
  return `${base}/.well-known/oauth-protected-resource${path}/mcp`;
}

// --- sealing ----------------------------------------------------------------

function seal(payload: object): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encKey(), iv);
  const plain = Buffer.from(JSON.stringify(payload));
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString("base64url");
}

function unseal(token: string): Record<string, unknown> | null {
  try {
    const raw = Buffer.from(token, "base64url");
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const enc = raw.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", encKey(), iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(enc), decipher.final()]);
    return JSON.parse(plain.toString()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

// --- redirect-URI policy ----------------------------------------------------

function isLoopback(uri: string): boolean {
  try {
    const u = new URL(uri);
    return (
      (u.protocol === "http:" || u.protocol === "https:") &&
      (u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]")
    );
  } catch {
    return false;
  }
}

function redirectAllowed(uri: string): boolean {
  if (isLoopback(uri)) return true;
  const allowed = (process.env.OAUTH_ALLOWED_REDIRECTS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return allowed.includes(uri);
}

// --- Tripletex validation ---------------------------------------------------

export type TokenKind = "jwt" | "employee";

/**
 * Which Tripletex credential did the user paste?
 *
 *   - "employee" — the personal key from ansattkortet -> API-tilganger, which
 *     Tripletex hands out as base64 of {"tokenId":<int>,"token":"<uuid>"}. It is
 *     redeemed together with OUR consumer token at PUT /token/session/:create.
 *   - "jwt" — the tlxr_ refresh secret from Selskap -> API-tokens, redeemed on
 *     its own at POST /token/session/:createFromRefreshToken.
 *
 * Only the employee shape is detected positively; everything else keeps taking
 * the historic refresh-token path, so setups that worked before are unaffected
 * and Tripletex stays the judge of what is actually valid.
 */
export function tokenKind(value: string): TokenKind {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64").toString()) as {
      tokenId?: unknown;
      token?: unknown;
    };
    if (typeof parsed?.tokenId === "number" && typeof parsed?.token === "string") {
      return "employee";
    }
  } catch {
    /* not base64 JSON — fall through to the refresh-token path */
  }
  return "jwt";
}

function tomorrow(): string {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  return d.toISOString().split("T")[0];
}

/**
 * Validate a pasted token by creating a real (short) Tripletex session on the
 * endpoint matching its kind. Returns null when the token works, otherwise the
 * message to show on the authorize page.
 */
async function validateTripletexToken(
  token: string,
  env: string,
  kind: TokenKind
): Promise<string | null> {
  const base = apiBase(env);

  if (kind === "employee") {
    const consumer = process.env.TRIPLETEX_CONSUMER_TOKEN ?? "";
    // No consumer token is a server misconfiguration, not a bad paste. Tripletex
    // answers 422 "Nøkkelen er ugyldig" on the consumerToken field, which would
    // otherwise be reported to the user as *their* key being wrong.
    if (!consumer) {
      return "Serveren mangler consumer token. Dette er en feil hos SkyeTec, ikke med nøkkelen din — kontakt oss.";
    }
    const url =
      `${base}/token/session/:create?consumerToken=${encodeURIComponent(consumer)}` +
      `&employeeToken=${encodeURIComponent(token)}&expirationDate=${tomorrow()}`;
    const res = await fetch(url, { method: "PUT" });
    if (res.ok) return null;
    const app = consumerName();
    return (
      "Tripletex avviste nøkkelen. Sjekk at hele verdien er kopiert, at den er opprettet " +
      "under ditt eget ansattkort → API-tilganger" +
      (app ? `, og at applikasjonsnavnet er «${app}»` : "") +
      "."
    );
  }

  const res = await fetch(`${base}/token/session/:createFromRefreshToken`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // Tripletex enforces a 300s minimum session ttl (422 "Må være minimum 300").
    body: JSON.stringify({ refreshToken: token, ttlSeconds: 300 }),
  });
  if (res.ok) return null;
  return (
    "Tripletex avviste tokenet. En personlig nøkkel fra ansattkortet → API-tilganger " +
    "begynner med «eyJ» — sjekk at hele verdien er med. Et tlxr_-token hentes fra " +
    "Selskap → API-tokens."
  );
}

// --- HTTP plumbing ----------------------------------------------------------

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString();
}

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function authorizePage(params: URLSearchParams, error?: string): string {
  const hidden = ["response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method"]
    .map((k) => `<input type="hidden" name="${k}" value="${esc(params.get(k) ?? "")}">`)
    .join("\n      ");
  const env = process.env.TRIPLETEX_ENV === "test" ? "test (api-test.tripletex.tech)" : "produksjon (tripletex.no)";
  const app = consumerName();
  return `<!doctype html>
<html lang="no"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Koble til Tripletex</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;color:#1a1a2e}
  input[type=password]{width:100%;padding:.6rem;font-family:monospace;font-size:.9rem}
  button{margin-top:1rem;padding:.6rem 1.4rem;font-size:1rem;background:#1a56db;color:#fff;border:0;border-radius:.35rem;cursor:pointer}
  .err{background:#fde8e8;border:1px solid #f8b4b4;padding:.6rem .8rem;border-radius:.35rem}
  ol{line-height:1.6} code{background:#f3f4f6;padding:.1rem .3rem;border-radius:.2rem}
</style></head><body>
  <h1>Koble til Tripletex</h1>
  <p>SkyeTec-rådgiveren ber om lesetilgang til Tripletex-miljøet <strong>${env}</strong> — med
  <em>din</em> Tripletex-bruker, slik at den bare ser det du selv har lov til å se.</p>
  <ol>
    <li>Logg inn i Tripletex og åpne ditt eget ansattkort — fanen <strong>API-tilganger</strong>.</li>
    <li>Opprett en ny nøkkel${app ? ` og oppgi applikasjonsnavnet <code>${esc(app)}</code>` : ""}.
        Kopier verdien (begynner med <code>eyJ</code>).</li>
    <li>Lim den inn her. Nøkkelen lagres aldri i klartekst — den forsegles kryptert inne i
        tilgangsnøkkelen denne påloggingen utsteder.</li>
  </ol>
  <p style="color:#555;font-size:.9rem">Har du i stedet et <code>tlxr_</code>-token fra
     Selskap → API-tokens, virker det også.</p>
  ${error ? `<p class="err">${esc(error)}</p>` : ""}
  <form method="post" action="${publicBaseUrl()}/authorize">
      ${hidden}
      <label for="token">Personlig API-token</label>
      <input type="password" id="token" name="token" autocomplete="off" required>
      <button type="submit">Koble til</button>
  </form>
</body></html>`;
}

// --- endpoints --------------------------------------------------------------

function metadata(): object {
  const base = publicBaseUrl();
  return {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    service_documentation: "https://github.com/SkyeTec-no/tripletex-mcp",
  };
}

function handleRegister(res: ServerResponse, body: string): void {
  let reg: { redirect_uris?: unknown };
  try {
    reg = JSON.parse(body) as { redirect_uris?: unknown };
  } catch {
    sendJson(res, 400, { error: "invalid_client_metadata", error_description: "body is not JSON" });
    return;
  }
  const uris = Array.isArray(reg.redirect_uris) ? reg.redirect_uris.filter((u): u is string => typeof u === "string") : [];
  if (!uris.length) {
    sendJson(res, 400, { error: "invalid_client_metadata", error_description: "redirect_uris is required" });
    return;
  }
  const refused = uris.filter((u) => !redirectAllowed(u));
  if (refused.length) {
    sendJson(res, 400, {
      error: "invalid_client_metadata",
      error_description: `redirect_uri not allowed: ${refused.join(", ")} — use loopback, or ask SkyeTec to allowlist it`,
    });
    return;
  }
  sendJson(res, 201, {
    client_id: seal({ k: "client", r: uris }),
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    redirect_uris: uris,
  });
}

function clientRedirects(clientId: string): string[] | null {
  const c = unseal(clientId);
  if (!c || c.k !== "client" || !Array.isArray(c.r)) return null;
  return c.r as string[];
}

function validAuthorizeParams(q: URLSearchParams): string | null {
  if (q.get("response_type") !== "code") return "response_type must be code";
  const redirects = clientRedirects(q.get("client_id") ?? "");
  if (!redirects) return "unknown client_id";
  if (!redirects.includes(q.get("redirect_uri") ?? "")) return "redirect_uri not registered for this client";
  if (q.get("code_challenge_method") !== "S256" || !q.get("code_challenge")) return "PKCE (S256) is required";
  return null;
}

async function handleAuthorizeSubmit(res: ServerResponse, body: string): Promise<void> {
  const form = new URLSearchParams(body);
  const bad = validAuthorizeParams(form);
  if (bad) {
    sendHtml(res, 400, authorizePage(form, bad));
    return;
  }
  const token = (form.get("token") ?? "").trim();
  const env = process.env.TRIPLETEX_ENV === "test" ? "test" : "prod";
  if (!token) {
    sendHtml(res, 400, authorizePage(form, "Fyll inn nøkkelen."));
    return;
  }
  const kind = tokenKind(token);
  const rejected = await validateTripletexToken(token, env, kind);
  if (rejected) {
    sendHtml(res, 400, authorizePage(form, rejected));
    return;
  }
  const code = seal({ k: "code", t: token, kind, c: form.get("code_challenge"), r: form.get("redirect_uri"), e: Date.now() + CODE_TTL_MS });
  const target = new URL(form.get("redirect_uri")!);
  target.searchParams.set("code", code);
  const state = form.get("state");
  if (state) target.searchParams.set("state", state);
  res.writeHead(302, { Location: target.toString() });
  res.end();
}

function mintTokens(secret: string, kind: TokenKind): object {
  return {
    access_token: seal({ k: "access", t: secret, kind, e: Date.now() + ACCESS_TTL_MS }),
    token_type: "Bearer",
    expires_in: Math.floor(ACCESS_TTL_MS / 1000),
    refresh_token: seal({ k: "refresh", t: secret, kind, e: Date.now() + REFRESH_TTL_MS }),
  };
}

/**
 * Tokens minted before employee-token support carry no `kind`. They are all
 * refresh-token secrets, so defaulting to "jwt" keeps every already-connected
 * client working across the deploy instead of silently logging it out.
 */
function sealedKind(v: unknown): TokenKind {
  return v === "employee" ? "employee" : "jwt";
}

function handleToken(res: ServerResponse, body: string): void {
  const form = new URLSearchParams(body);
  const grant = form.get("grant_type");
  if (grant === "authorization_code") {
    const code = unseal(form.get("code") ?? "");
    if (!code || code.k !== "code" || typeof code.t !== "string" || (code.e as number) < Date.now()) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "code invalid or expired" });
      return;
    }
    if (form.get("redirect_uri") !== code.r) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
      return;
    }
    const verifier = form.get("code_verifier") ?? "";
    const expect = Buffer.from(String(code.c ?? ""));
    const got = Buffer.from(createHash("sha256").update(verifier).digest("base64url"));
    if (expect.length !== got.length || !timingSafeEqual(expect, got)) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
      return;
    }
    sendJson(res, 200, mintTokens(code.t, sealedKind(code.kind)));
    return;
  }
  if (grant === "refresh_token") {
    const rt = unseal(form.get("refresh_token") ?? "");
    if (!rt || rt.k !== "refresh" || typeof rt.t !== "string" || (rt.e as number) < Date.now()) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "refresh token invalid or expired" });
      return;
    }
    sendJson(res, 200, mintTokens(rt.t, sealedKind(rt.kind)));
    return;
  }
  sendJson(res, 400, { error: "unsupported_grant_type" });
}

export interface BearerAuth {
  /** The Tripletex secret sealed at /authorize. */
  token: string;
  /** Which Tripletex session flow redeems it. */
  kind: TokenKind;
  /**
   * Stable, non-reversible per-caller id. Used to scope server-side caches so
   * two users cannot collide on a shared cache key; safe to log.
   */
  scope: string;
}

/**
 * The Bearer gate for /mcp. Returns the sealed Tripletex credential when the
 * header is valid, null when it is missing/invalid (caller answers 401), and
 * "off" when OAuth is not configured (caller falls back to legacy header auth).
 */
export function tripletexTokenFromBearer(req: IncomingMessage): BearerAuth | null | "off" {
  if (!oauthEnabled()) return "off";
  const header = req.headers.authorization ?? "";
  const match = /^Bearer (.+)$/.exec(Array.isArray(header) ? header[0] : header);
  if (!match) return null;
  const tok = unseal(match[1]);
  if (!tok || tok.k !== "access" || typeof tok.t !== "string" || (tok.e as number) < Date.now()) return null;
  return {
    token: tok.t,
    kind: sealedKind(tok.kind),
    scope: createHash("sha256").update(tok.t).digest("base64url").slice(0, 16),
  };
}

export function send401(res: ServerResponse): void {
  res.writeHead(401, {
    "Content-Type": "application/json",
    "WWW-Authenticate": `Bearer resource_metadata="${resourceMetadataUrl()}"`,
  });
  res.end(JSON.stringify({ error: "invalid_token" }));
}

/** Route OAuth endpoints. Returns true when the request was handled here. */
export async function handleOAuth(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL
): Promise<boolean> {
  if (!oauthEnabled()) return false;
  const { pathname } = url;

  if ((pathname === "/.well-known/oauth-authorization-server" || pathname.startsWith("/.well-known/oauth-authorization-server/")) && req.method === "GET") {
    sendJson(res, 200, metadata());
    return true;
  }
  if ((pathname === "/.well-known/oauth-protected-resource" || pathname.startsWith("/.well-known/oauth-protected-resource/")) && req.method === "GET") {
    sendJson(res, 200, {
      resource: `${publicResourceUrl()}/mcp`,
      authorization_servers: [publicBaseUrl()],
    });
    return true;
  }
  if (pathname === "/register" && req.method === "POST") {
    handleRegister(res, await readBody(req));
    return true;
  }
  if (pathname === "/authorize" && req.method === "GET") {
    const bad = validAuthorizeParams(url.searchParams);
    sendHtml(res, bad ? 400 : 200, authorizePage(url.searchParams, bad ?? undefined));
    return true;
  }
  if (pathname === "/authorize" && req.method === "POST") {
    await handleAuthorizeSubmit(res, await readBody(req));
    return true;
  }
  if (pathname === "/token" && req.method === "POST") {
    handleToken(res, await readBody(req));
    return true;
  }
  return false;
}
