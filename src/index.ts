import { app } from "./app";
import { runScheduled } from "./scheduled";

export default {
  fetch(
    request: Request,
    env: Omit<Parameters<typeof app.fetch>[1], "EXECUTION_CONTEXT">,
    context: ExecutionContext,
  ): Response | Promise<Response> {
    return app.fetch(request, { ...env, EXECUTION_CONTEXT: context }, context);
  },
  scheduled(
    _controller: ScheduledController,
    env: Parameters<typeof runScheduled>[0],
    context: ExecutionContext,
  ): void {
    context.waitUntil(runScheduled(env));
  },
};
