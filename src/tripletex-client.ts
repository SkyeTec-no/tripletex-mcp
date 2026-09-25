/**
 * Tripletex API Client
 * Handles authentication and HTTP requests to the Tripletex REST API.
 */

const PROD_BASE = "https://tripletex.no/v2";
const TEST_BASE = "https://api-test.tripletex.tech/v2";

interface SessionToken {
  token: string;
  /** Epoch ms when we stop reusing this token and create a new one. */
  expiresAtMs: number;
}

/** Session lifetime for the JWT flow. Tripletex rejects anything over 28800
 * ("Kan ikke være over 28800"), so 8h is the ceiling, not a choice. */
const DEFAULT_TTL_SECONDS = 8 * 60 * 60;
/** Renew a little early so a long request never runs past the expiry. */
const RENEW_MARGIN_MS = 60 * 1000;

export class TripletexApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly bodyText: string
  ) {
    super(message);
    this.name = "TripletexApiError";
  }
}

/**
 * Credentials passed in per client instance. Anything omitted falls back to the
 * corresponding environment variable, so a single-tenant deployment can keep
 * configuring everything through the environment.
 */
export interface TripletexCredentials {
  jwt?: string;
  consumerToken?: string;
  employeeToken?: string;
  /**
   * Pin the session flow instead of inferring it from which fields are set, and
   * suppress the environment fallback for the credential the other flow uses.
   * The OAuth path must set this: with TRIPLETEX_JWT configured for a
   * single-tenant deployment, an employee-token session would otherwise fall
   * back to the environment JWT and silently run as the wrong user.
   */
  kind?: "jwt" | "employee";
  /** "test" targets api-test.tripletex.tech. */
  env?: string;
  ttlSeconds?: number;
}

export class TripletexClient {
  private refreshToken: string;
  private consumerToken: string;
  private employeeToken: string;
  private kind: "jwt" | "employee";
  private ttlSeconds: number;
  private baseUrl: string;
  private session: SessionToken | null = null;

  constructor(credentials: TripletexCredentials = {}) {
    // Two ways to authenticate, see
    // https://developer.tripletex.no/docs/documentation/authentication-and-tokens/
    //
    //   1. Internal integration (one company / company group): a user-admin
    //      creates a JWT under Selskap -> API-tokens in Tripletex. No consumer
    //      token, and no application to Tripletex. This is the simple path.
    //   2. Commercial integration (many customers): consumer token from
    //      Tripletex + an employee token created by each end customer.
    // An explicit kind means the caller knows which credential it holds; only
    // consult the environment for the flow that kind actually uses.
    const refresh =
      credentials.kind === "employee"
        ? ""
        : credentials.jwt ||
          process.env.TRIPLETEX_JWT ||
          process.env.TRIPLETEX_REFRESH_TOKEN ||
          "";
    const consumer =
      credentials.consumerToken || process.env.TRIPLETEX_CONSUMER_TOKEN || "";
    const employee =
      credentials.kind === "jwt"
        ? ""
        : credentials.employeeToken || process.env.TRIPLETEX_EMPLOYEE_TOKEN || "";
    if (!refresh && !employee) {
      throw new Error(
        "Missing Tripletex credentials. Set TRIPLETEX_JWT (internal integration: " +
          "Selskap -> API-tokens in Tripletex), or TRIPLETEX_CONSUMER_TOKEN + " +
          "TRIPLETEX_EMPLOYEE_TOKEN (commercial integration). Over HTTP transport " +
          "these can also be sent per request as X-Tripletex-Jwt / " +
          "X-Tripletex-Consumer-Token / X-Tripletex-Employee-Token."
      );
    }
    this.kind = credentials.kind ?? (refresh ? "jwt" : "employee");
    // Tripletex rejects :create without a consumer token (422, validation on the
    // consumerToken field), so an employee token alone can never work. Fail here
    // with the cause rather than on the first tool call with a 422 body.
    if (this.kind === "employee" && !consumer) {
      throw new Error(
        "An employee token requires a consumer token. Set TRIPLETEX_CONSUMER_TOKEN " +
          "(or send X-Tripletex-Consumer-Token) — Tripletex rejects " +
          "/token/session/:create without it."
      );
    }
    this.refreshToken = refresh;
    this.consumerToken = consumer;
    this.employeeToken = employee;
    this.ttlSeconds =
      credentials.ttlSeconds ||
      Number(process.env.TRIPLETEX_SESSION_TTL_SECONDS) ||
      DEFAULT_TTL_SECONDS;
    const env = credentials.env || process.env.TRIPLETEX_ENV;
    this.baseUrl = env === "test" ? TEST_BASE : PROD_BASE;
  }

  private async createSession(): Promise<void> {
    this.session =
      this.kind === "jwt"
        ? await this.createSessionFromJwt()
        : await this.createSessionFromTokenPair();
  }

  /** Internal integration: exchange the JWT secret for a session token. */
  private async createSessionFromJwt(): Promise<SessionToken> {
    const res = await fetch(
      `${this.baseUrl}/token/session/:createFromRefreshToken`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          refreshToken: this.refreshToken,
          ttlSeconds: this.ttlSeconds,
        }),
      }
    );
    const text = await res.text();
    if (!res.ok) {
      throw new TripletexApiError(
        `Session create from JWT failed (${res.status})`,
        res.status,
        text
      );
    }
    // Tripletex wraps most responses in { value: ... }; accept both shapes.
    let parsed: { value?: { token?: string }; token?: string };
    try {
      parsed = JSON.parse(text) as typeof parsed;
    } catch {
      throw new TripletexApiError(
        "Session create from JWT returned non-JSON",
        res.status,
        text
      );
    }
    const token = parsed.value?.token ?? parsed.token;
    if (!token) {
      throw new TripletexApiError(
        "Session create from JWT returned no token",
        res.status,
        text
      );
    }
    return {
      token,
      expiresAtMs: Date.now() + this.ttlSeconds * 1000 - RENEW_MARGIN_MS,
    };
  }

  /** Commercial integration: consumer token + employee token. */
  private async createSessionFromTokenPair(): Promise<SessionToken> {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const expDate = tomorrow.toISOString().split("T")[0];

    const url = `${this.baseUrl}/token/session/:create?consumerToken=${encodeURIComponent(this.consumerToken)}&employeeToken=${encodeURIComponent(this.employeeToken)}&expirationDate=${expDate}`;

    const res = await fetch(url, { method: "PUT" });
    if (!res.ok) {
      const text = await res.text();
      throw new TripletexApiError(
        `Session create failed (${res.status})`,
        res.status,
        text
      );
    }
    const data = (await res.json()) as { value: { token: string } };
    // These tokens expire at midnight CET on expirationDate, so treat the start
    // of that date as the cutoff — the 401 retry covers the remaining slack.
    return {
      token: data.value.token,
      expiresAtMs: new Date(`${expDate}T00:00:00`).getTime(),
    };
  }

  private async ensureSession(): Promise<string> {
    if (!this.session || this.session.expiresAtMs <= Date.now()) {
      await this.createSession();
    }
    return this.session!.token;
  }

  private authHeader(sessionToken: string): string {
    return "Basic " + Buffer.from(`0:${sessionToken}`).toString("base64");
  }

  async request(
    method: string,
    path: string,
    params?: Record<string, string>,
    body?: unknown,
    isRetry = false
  ): Promise<unknown> {
    const token = await this.ensureSession();
    const url = new URL(`${this.baseUrl}${path}`);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        url.searchParams.set(k, v);
      }
    }

    const headers: Record<string, string> = {
      Authorization: this.authHeader(token),
      "Content-Type": "application/json",
    };

    const res = await fetch(url.toString(), {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (res.status === 401 && !isRetry) {
      this.session = null;
      return this.request(method, path, params, body, true);
    }

    const text = await res.text();

    if (!res.ok) {
      throw new TripletexApiError(
        `Tripletex ${method} ${path} (${res.status})`,
        res.status,
        text
      );
    }

    if (!text) return {};
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return text;
    }
  }

  /** True when this client's calls go to api-test.tripletex.tech. Resolved per client
   *  from credentials.env || TRIPLETEX_ENV, so on the header-auth HTTP path a caller can
   *  steer it — test-only tools must check THIS, not process.env. */
  targetsTestEnvironment(): boolean {
    return this.baseUrl === TEST_BASE;
  }

  async get(path: string, params?: Record<string, string>) {
    return this.request("GET", path, params);
  }

  async post(path: string, body: unknown, params?: Record<string, string>) {
    return this.request("POST", path, params, body);
  }

  async put(path: string, body: unknown, params?: Record<string, string>) {
    return this.request("PUT", path, params, body);
  }

  async delete(path: string, params?: Record<string, string>) {
    return this.request("DELETE", path, params);
  }
}
