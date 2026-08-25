export async function request(
  url: URL,
  authorization: string,
  init?: RequestInit,
): Promise<Response> {
  // `init.headers` may be a Headers instance or a tuple array, neither of which
  // survives object spread, so merge through Headers before setting the managed ones.
  const headers = new Headers(init?.headers);
  headers.set("authorization", authorization);
  headers.set("content-type", "application/json");
  return fetch(url, { ...init, headers, signal: AbortSignal.timeout(10_000) });
}
