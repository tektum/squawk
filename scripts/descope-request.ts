export async function request(
  url: URL,
  authorization: string,
  init?: RequestInit,
): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: { authorization, "content-type": "application/json", ...init?.headers },
    signal: AbortSignal.timeout(10_000),
  });
}
