// Calls of the REST API of the core (ADR-0020, § 3). Same origin only; the
// session is the HttpOnly cookie, never seen by this code. The portal shows
// stable codes, never a free text from the server.

/** The current session, as `GET /api/v1/session` returns it. */
export interface SessionInfo {
  login_session: string;
  user: string;
  username: string;
  display_name: string;
  roles: string[];
  authenticated_at: number;
  expires_at: number;
  idle_expires_at: number;
}

/** A refusal: the stable code of the core, or a local one. */
export class ApiError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

/** Local code: the core could not be reached or answered something else. */
export const UNREACHABLE = "PORTAL-E001";

const CODE = /^[A-Z]{2,5}-E[0-9]{3}$/;

async function refusal(response: Response): Promise<ApiError> {
  try {
    const body: unknown = await response.json();
    if (typeof body === "object" && body !== null && "code" in body) {
      const code = (body as { code: unknown }).code;
      if (typeof code === "string" && CODE.test(code)) {
        return new ApiError(code);
      }
    }
  } catch {
    // Not JSON: reported as unreachable below.
  }
  return new ApiError(UNREACHABLE);
}

async function call(
  method: string,
  path: string,
  body?: unknown,
  background = false,
): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  // Every method that changes state declares JSON, body or not: the core
  // refuses it otherwise (CSRF, WEB-E003), and the browser preflights it.
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
  }
  if (background) {
    headers["X-Ostena-Background"] = "1";
  }
  const init: RequestInit = {
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  try {
    return await fetch(path, init);
  } catch {
    throw new ApiError(UNREACHABLE);
  }
}

/** The open session, or `null` without one. */
export async function currentSession(): Promise<SessionInfo | null> {
  const response = await call("GET", "/api/v1/session", undefined, true);
  if (response.status === 401) {
    return null;
  }
  if (!response.ok) {
    throw await refusal(response);
  }
  return (await response.json()) as SessionInfo;
}

/** Opens a session with the two factors, in one request. */
export async function login(
  username: string,
  password: string,
  totp: string,
): Promise<SessionInfo> {
  const response = await call("POST", "/api/v1/session", {
    username,
    password,
    totp,
  });
  if (!response.ok) {
    throw await refusal(response);
  }
  return (await response.json()) as SessionInfo;
}

/** Closes the session. */
export async function logout(): Promise<void> {
  const response = await call("DELETE", "/api/v1/session");
  if (!response.ok && response.status !== 401) {
    throw await refusal(response);
  }
}
