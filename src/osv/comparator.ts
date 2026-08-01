import matcherModule from "../generated/osv_matcher.wasm";
import "../generated/wasm_exec.js";
import { z } from "zod";

const eventSchema = z.object({
  introduced: z.string().optional(),
  fixed: z.string().optional(),
  last_affected: z.string().optional(),
  limit: z.string().optional(),
});
export const comparisonInputSchema = z.object({
  ecosystem: z.string().min(1),
  version: z.string().min(1),
  ranges: z.array(z.object({ type: z.string(), events: z.array(eventSchema) })).default([]),
  versions: z.array(z.string()).default([]),
});
const comparisonSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("match") }),
  z.object({ kind: z.literal("no_match") }),
  z.object({ kind: z.literal("unsupported"), reason: z.string() }),
  z.object({ kind: z.literal("error"), reason: z.string() }),
]);
export type Comparison = z.infer<typeof comparisonSchema>;
export type ComparisonInput = z.infer<typeof comparisonInputSchema>;

let started: Promise<void> | undefined;

async function start(): Promise<void> {
  if (started) return started;
  started = (async () => {
    const go = new Go();
    const instance = await WebAssembly.instantiate(matcherModule, go.importObject);
    void go.run(instance);
    await scheduler.wait(0);
  })();
  try {
    await started;
  } catch (error) {
    started = undefined;
    throw error;
  }
}

export async function compareVersion(input: ComparisonInput): Promise<Comparison> {
  try {
    await start();
    const comparator = z
      .function({ input: [z.string()], output: z.string() })
      .parse(Reflect.get(globalThis, "squawkCompare"));
    return comparisonSchema.parse(
      JSON.parse(comparator(JSON.stringify(comparisonInputSchema.parse(input)))),
    );
  } catch (error) {
    return {
      kind: "error",
      reason: error instanceof Error ? error.message : "Wasm comparator failed",
    };
  }
}
