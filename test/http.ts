import { http, HttpResponse } from "msw";
import { server } from "./server";

type MockResponse = {
  readonly body?: unknown;
  readonly method?: "GET" | "POST";
  readonly status: number;
  readonly text?: string;
  readonly url: string;
};

export function respond(response: MockResponse): void {
  const resolver = () =>
    response.text === undefined
      ? response.body === undefined
        ? new HttpResponse(null, { status: response.status })
        : HttpResponse.json(response.body, { status: response.status })
      : new HttpResponse(response.text, { status: response.status });

  switch (response.method ?? "GET") {
    case "GET":
      server.use(http.get(response.url, resolver));
      return;
    case "POST":
      server.use(http.post(response.url, resolver));
      return;
  }
}
