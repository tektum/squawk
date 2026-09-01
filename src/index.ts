import { recordActivity } from "./activity";
import { advisoryMessageSchema, processAdvisory } from "./advisory";
import { app } from "./app";
import { dispatchMessageSchema } from "./dispatch";
import { dispatchOne } from "./dispatch-worker";
import { describeError } from "./error-detail";
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
    // One Worker consumes every queue, so the batch's own queue decides the handler.
    // Dead-letter batches are recorded rather than reprocessed: a message that already
    // exhausted its retries would only fail again, and silently accumulating in a queue
    // nobody reads is how a failure stops being visible.
    if (batch.queue.endsWith("-dlq")) {
      await recordDeadLetters(batch, env.DB);
      return;
    }
    if (batch.queue.endsWith("-finding-dispatch")) {
      await consumeDispatch(batch, env);
      return;
    }
    await consumeAdvisories(batch, env);
  },
};

async function recordDeadLetters(batch: MessageBatch, database: D1Database): Promise<void> {
  const dispatch = batch.queue.includes("finding-dispatch");
  const kind = dispatch ? "dispatch" : "advisory";
  for (const message of batch.messages) {
    if (dispatch) {
      const parsed = dispatchMessageSchema.safeParse(message.body);
      if (parsed.success)
        await database
          .prepare(
            "UPDATE dispatch_deliveries SET status='failed',attempted_at=?,error='dead-letter queue' WHERE delivery_id=? AND status='pending'",
          )
          .bind(Date.now(), parsed.data.deliveryId)
          .run();
    }
    await recordActivity(database, kind, "failed");
    console.error("Queue message exhausted its retries", { queue: batch.queue });
    message.ack();
  }
}

async function consumeDispatch(
  batch: MessageBatch,
  env: Parameters<typeof runScheduled>[0],
): Promise<void> {
  for (const message of batch.messages) {
    try {
      const accepted = await dispatchOne(env, dispatchMessageSchema.parse(message.body));
      await recordActivity(env.DB, "dispatch", accepted ? "accepted" : "failed");
      message.ack();
    } catch (error) {
      // The delivery row already carries the reason; the queue owns the backoff.
      console.error("Queued dispatch failed", { error: describeError(error) });
      message.retry();
    }
  }
}

async function consumeAdvisories(
  batch: MessageBatch,
  env: Parameters<typeof runScheduled>[0],
): Promise<void> {
  for (const message of batch.messages) {
    try {
      await processAdvisory({
        database: env.DB,
        message: advisoryMessageSchema.parse(message.body),
        osvBaseUrl: env.OSV_BASE_URL,
      });
      await recordActivity(env.DB, "advisory", "completed");
      message.ack();
    } catch {
      await recordActivity(env.DB, "advisory", "failed");
      message.retry({ delaySeconds: 60 });
    }
  }
}
