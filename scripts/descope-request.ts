export async function request(
  url: URL,
  authorization: string,
  init?: RequestInit,
): Promise<Response> {
  // The management key is a bearer credential, so refuse to attach it to a plaintext
  // destination even though the input schema only validates URL syntax.
  if (url.protocol !== "https:") throw new Error("Descope base URL must use https");
  // `init.headers` may be a Headers instance or a tuple array, neither of which
  // survives object spread, so merge through Headers before setting the managed ones.
  const headers = new Headers(init?.headers);
  headers.set("authorization", authorization);
  headers.set("content-type", "application/json");
  // Keep any caller cancellation alongside the timeout rather than replacing it.
  const timeout = AbortSignal.timeout(10_000);
  const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
  return fetch(url, { ...init, headers, signal });
}
