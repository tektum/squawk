import { getSessionToken, isSessionTokenExpired, refresh } from "@descope/react-sdk/flows";
import { useEffect, useState } from "react";

export class ApiError extends Error {
  readonly name = "ApiError";
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/* Descope keeps the session; the panel only reads it. Refreshing before a call rather
   than reacting to a 401 keeps a long-lived tab from losing an operator's place. */
async function authorization(): Promise<string> {
  if (isSessionTokenExpired()) await refresh();
  const token = getSessionToken();
  if (!token) throw new ApiError(401, "Session expired");
  return `Bearer ${token}`;
}

async function call(method: string, path: string, body?: unknown): Promise<Response> {
  const response = await fetch(path, {
    method,
    headers: {
      authorization: await authorization(),
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (response.ok) return response;
  const detail = (await response.json().catch(() => ({}))) as { error?: string };
  throw new ApiError(response.status, detail.error ?? response.statusText);
}

export async function get<T>(path: string): Promise<T> {
  return (await (await call("GET", path)).json()) as T;
}

export async function send(method: string, path: string, body?: unknown): Promise<void> {
  await call(method, path, body);
}

export type Resource<T> = {
  readonly data: T | null;
  readonly error: string | null;
  readonly loading: boolean;
};

export function useResource<T>(path: string, reloadKey = 0): Resource<T> {
  const [state, setState] = useState<Resource<T>>({ data: null, error: null, loading: true });
  useEffect(() => {
    let live = true;
    const url =
      reloadKey === 0 ? path : `${path}${path.includes("?") ? "&" : "?"}reload=${reloadKey}`;
    setState((current) => ({ ...current, loading: true }));
    get<T>(url)
      .then((data) => live && setState({ data, error: null, loading: false }))
      .catch(
        (error: unknown) =>
          live &&
          setState({
            data: null,
            error:
              error instanceof ApiError && error.status === 403
                ? "This account is missing the capability for that view."
                : error instanceof Error
                  ? error.message
                  : "Request failed",
            loading: false,
          }),
      );
    return () => {
      live = false;
    };
  }, [path, reloadKey]);
  return state;
}
