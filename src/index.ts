import { advisoryMessageSchema, processAdvisory } from "./advisory";
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
  async queue(
    batch: MessageBatch,
    env: Parameters<typeof runScheduled>[0],
    _context?: ExecutionContext,
  ): Promise<void> {
    for (const message of batch.messages) {
      try {
        await processAdvisory({
          database: env.DB,
          message: advisoryMessageSchema.parse(message.body),
          osvBaseUrl: env.OSV_BASE_URL,
        });
        message.ack();
      } catch {
        message.retry({ delaySeconds: 60 });
      }
    }
  },
};
