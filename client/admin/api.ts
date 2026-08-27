import { createContext, useContext, useEffect, useState } from "react";
import type * as z from "zod/mini";

export class ApiError extends Error {
  readonly name = "ApiError";
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/* The session token comes from `useSession()` through this context rather than from the
   SDK's standalone `getSessionToken`: that helper is installed by the persistTokens
   enhancer, so it does not exist when tokens are kept out of browser storage. The
   provider keeps the current token in one place; AuthProvider refreshes it. */
const TokenContext = createContext<string>("");
export const TokenProvider = TokenContext.Provider;

async function call(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  const publicPath = path.startsWith("/public/");
  if (!token && !publicPath) throw new ApiError(401, "Session expired");
  const response = await fetch(path, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
  });
  if (response.ok) return response;
  const detail = (await response.json().catch(() => ({}))) as { error?: string };
  throw new ApiError(response.status, detail.error ?? response.statusText);
}

async function get<T>(token: string, path: string, schema: z.ZodMiniType<T>): Promise<T> {
  const parsed = schema.safeParse(await (await call(token, "GET", path)).json());
  if (!parsed.success) throw new ApiError(502, "Unexpected response from Squawk");
  return parsed.data;
}

export type Send = (method: string, path: string, body?: unknown) => Promise<void>;

export function useSend(): Send {
  const token = useContext(TokenContext);
  return async (method, path, body) => {
    await call(token, method, path, body);
  };
}

export type Resource<T> = {
  readonly data: T | null;
  readonly error: string | null;
  readonly loading: boolean;
};

export function useResource<T>(path: string, schema: z.ZodMiniType<T>, reloadKey = 0): Resource<T> {
  const token = useContext(TokenContext);
  const [state, setState] = useState<Resource<T>>({ data: null, error: null, loading: true });
  useEffect(() => {
    let live = true;
    const url =
      reloadKey === 0 ? path : `${path}${path.includes("?") ? "&" : "?"}reload=${reloadKey}`;
    setState((current) => ({ ...current, loading: true }));
    get(token, url, schema)
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
  }, [token, path, schema, reloadKey]);
  return state;
}
