import worker from "../src/index";

export type SentMessage = { readonly body: unknown };

export type RecordingQueue = {
  readonly queue: Queue;
  readonly sent: readonly SentMessage[];
};

/** Captures what a producer sends, so a test can assert the enqueue without draining it. */
export function recordingQueue(): RecordingQueue {
  const sent: SentMessage[] = [];
  const queue = {
    async send(body: unknown) {
      sent.push({ body });
    },
    async sendBatch(messages: Iterable<{ body: unknown }>) {
      for (const message of messages) sent.push({ body: message.body });
    },
  } as unknown as Queue;
  return { queue, sent };
}

export type DrainResult = {
  readonly acked: number;
  readonly retried: number;
};

/**
 * Delivers bodies to the Worker's real `queue` handler as one batch, so the test exercises
 * queue routing, activity recording and the ack/retry decision rather than a handler called
 * directly. `name` matters: the handler routes on the queue's name.
 */
export async function drainQueue(
  name: string,
  bodies: readonly unknown[],
  env: unknown,
): Promise<DrainResult> {
  let acked = 0;
  let retried = 0;
  const messages = bodies.map((body, index) => ({
    id: `message-${index}`,
    timestamp: new Date(),
    body,
    attempts: 1,
    ack() {
      acked += 1;
    },
    retry() {
      retried += 1;
    },
  }));
  const batch = {
    queue: name,
    messages,
    ackAll() {
      acked += messages.length;
    },
    retryAll() {
      retried += messages.length;
    },
  } as unknown as MessageBatch;
  await worker.queue(batch, env as Parameters<typeof worker.queue>[1]);
  return { acked, retried };
}
