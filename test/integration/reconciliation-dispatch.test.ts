import { env } from "cloudflare:test";
import { exportPKCS8, generateKeyPair } from "jose";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { dispatchMessageSchema } from "../../src/dispatch";
import { dispatchOne } from "../../src/dispatch-worker";
import { enqueueReconciliations } from "../../src/reconciliation-dispatch";
import { recordingQueue } from "../queue";
import { server } from "../server";

const logical = `ghcr.io/owner/demo@sha256:${"a".repeat(64)}`;

describe("reconciliation workflow dispatch", () => {
  let privateKey: string;

  beforeEach(async () => {
    privateKey = await exportPKCS8(
      (await generateKeyPair("RS256", { extractable: true })).privateKey,
    );
    await env.DB.batch([
      env.DB.prepare("INSERT INTO orgs VALUES ('tenant','app',0)"),
      env.DB.prepare(
        "INSERT INTO github_sources (installation_id,repository_id,org_id,dispatch_workflow,dispatch_ref,created_at,dispatch_schema_version) VALUES ('123','9','tenant','monitor.yaml','main',0,2)",
      ),
      env.DB.prepare(
        "INSERT INTO reconciliation_checkpoints VALUES (?,'123','9',?,1,'ready',NULL,'{}',?,0)",
      ).bind("c".repeat(64), logical, "d".repeat(64)),
      env.DB.prepare(
        "INSERT INTO image_reconciliation_state (installation_id,repository_id,logical_image_ref,revision,state,reason,checkpoint_id,applied_revision,inventory_generation,state_sha256,updated_at) VALUES ('123','9',?,1,'ready',NULL,?,0,0,?,0)",
      ).bind(logical, "c".repeat(64), "e".repeat(64)),
    ]);
  });

  it("captures the workflow run id and retries only after terminal missing ack", async () => {
    server.use(
      http.post("https://api.github.com/app/installations/123/access_tokens", () =>
        HttpResponse.json({ token: "installation-token" }, { status: 201 }),
      ),
      http.get("https://api.github.com/repositories/9", () =>
        HttpResponse.json({ full_name: "owner/repo" }),
      ),
      http.post(
        "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
        async ({ request }) => {
          const body = (await request.json()) as { inputs?: { payload?: string } };
          expect(JSON.parse(body.inputs?.payload ?? "{}")).toEqual({
            schema_version: 2,
            event: "reconcile",
            delivery_id: expect.stringMatching(/^[a-f0-9]{64}$/),
            logical_image_ref: logical,
            source: { installation_id: "123", repository_id: "9" },
          });
          return HttpResponse.json({ workflow_run_id: 77, run_url: "url", html_url: "html" });
        },
      ),
    );
    const producer = recordingQueue();
    const bindings = {
      DB: env.DB,
      GH_APP_ID: "42",
      GH_APP_INSTALLATION_ID: "123",
      GH_APP_PRIVATE_KEY: privateKey,
      FINDING_DISPATCH: producer.queue,
    };

    await expect(enqueueReconciliations(bindings, 1_000)).resolves.toBe(1);
    const message = dispatchMessageSchema.parse(producer.sent[0]?.body);
    await expect(dispatchOne(bindings, message, 2_000)).resolves.toBe(true);
    await expect(
      env.DB.prepare(
        "SELECT status || ':' || workflow_run_id || ':' || workflow_ref_sha256 FROM reconciliation_deliveries",
      ).first("status || ':' || workflow_run_id || ':' || workflow_ref_sha256"),
    ).resolves.toBe(
      "dispatched:77:9c8629e077b28b0fe69f38b3b14ba13b4de8c9e40b80d498fbb7ed2273962eae",
    );

    server.use(
      http.get("https://api.github.com/repos/owner/repo/actions/runs/77", () =>
        HttpResponse.json({ status: "completed", conclusion: "failure" }),
      ),
    );
    const recovery = recordingQueue();
    await expect(
      enqueueReconciliations({ ...bindings, FINDING_DISPATCH: recovery.queue }, 3_000),
    ).resolves.toBe(1);
    expect(recovery.sent).toHaveLength(1);
    expect(recovery.sent[0]?.body).toEqual(message);
    await expect(
      env.DB.prepare("SELECT workflow_run_id FROM reconciliation_deliveries").first(
        "workflow_run_id",
      ),
    ).resolves.toBeNull();
  });

  it("cannot clear a newer run with a delayed terminal response", async () => {
    server.use(
      http.post("https://api.github.com/app/installations/123/access_tokens", () =>
        HttpResponse.json({ token: "installation-token" }, { status: 201 }),
      ),
      http.get("https://api.github.com/repositories/9", () =>
        HttpResponse.json({ full_name: "owner/repo" }),
      ),
      http.post(
        "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
        () => HttpResponse.json({ workflow_run_id: 77, run_url: "url", html_url: "html" }),
      ),
    );
    const producer = recordingQueue();
    const bindings = {
      DB: env.DB,
      GH_APP_ID: "42",
      GH_APP_INSTALLATION_ID: "123",
      GH_APP_PRIVATE_KEY: privateKey,
      FINDING_DISPATCH: producer.queue,
    };
    await enqueueReconciliations(bindings, 1_000);
    const message = dispatchMessageSchema.parse(producer.sent[0]?.body);
    await dispatchOne(bindings, message, 2_000);

    let releaseGate: () => void = () => undefined;
    let markStarted: () => void = () => undefined;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });
    server.use(
      http.get("https://api.github.com/repos/owner/repo/actions/runs/77", async () => {
        markStarted();
        await gate;
        return HttpResponse.json({ status: "completed", conclusion: "failure" });
      }),
    );
    const recovery = enqueueReconciliations(
      { ...bindings, FINDING_DISPATCH: recordingQueue().queue },
      3_000,
    );
    await started;
    await env.DB.prepare(
      `UPDATE reconciliation_deliveries SET workflow_run_id='78',attempt_id='attempt-r2',
        attempted_at=2500 WHERE delivery_id=? AND status='dispatched'`,
    )
      .bind(message.deliveryId)
      .run();
    releaseGate();

    await expect(recovery).resolves.toBe(0);
    await expect(
      env.DB.prepare(
        "SELECT workflow_run_id || ':' || attempt_id FROM reconciliation_deliveries",
      ).first("workflow_run_id || ':' || attempt_id"),
    ).resolves.toBe("78:attempt-r2");
  });

  it("cannot reset a newer attempt with a delayed failure", async () => {
    let releaseFailure: () => void = () => undefined;
    let markStarted: () => void = () => undefined;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      releaseFailure = resolve;
    });
    server.use(
      http.post("https://api.github.com/app/installations/123/access_tokens", async () => {
        markStarted();
        await gate;
        return HttpResponse.json({ error: "unavailable" }, { status: 503 });
      }),
    );
    const producer = recordingQueue();
    const bindings = {
      DB: env.DB,
      GH_APP_ID: "42",
      GH_APP_INSTALLATION_ID: "123",
      GH_APP_PRIVATE_KEY: privateKey,
      FINDING_DISPATCH: producer.queue,
    };
    await enqueueReconciliations(bindings, 1_000);
    const message = dispatchMessageSchema.parse(producer.sent[0]?.body);
    const dispatch = dispatchOne(bindings, message, 2_000);
    await started;
    await env.DB.prepare(
      "UPDATE reconciliation_deliveries SET attempt_id='new-attempt',attempted_at=2500 WHERE delivery_id=?",
    )
      .bind(message.deliveryId)
      .run();
    releaseFailure();

    await expect(dispatch).resolves.toBe(false);
    await expect(
      env.DB.prepare("SELECT status || ':' || attempt_id FROM reconciliation_deliveries").first(
        "status || ':' || attempt_id",
      ),
    ).resolves.toBe("pending:new-attempt");
  });

  it("releases a pre-dispatch transport failure for one later retry", async () => {
    let tokenCalls = 0;
    let dispatches = 0;
    server.use(
      http.post("https://api.github.com/app/installations/123/access_tokens", () => {
        tokenCalls += 1;
        return tokenCalls === 1
          ? HttpResponse.error()
          : HttpResponse.json({ token: "installation-token" }, { status: 201 });
      }),
      http.get("https://api.github.com/repositories/9", () =>
        HttpResponse.json({ full_name: "owner/repo" }),
      ),
      http.post(
        "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
        () => {
          dispatches += 1;
          return HttpResponse.json({ workflow_run_id: 77, run_url: "url", html_url: "html" });
        },
      ),
    );
    const producer = recordingQueue();
    const bindings = {
      DB: env.DB,
      GH_APP_ID: "42",
      GH_APP_INSTALLATION_ID: "123",
      GH_APP_PRIVATE_KEY: privateKey,
      FINDING_DISPATCH: producer.queue,
    };
    await enqueueReconciliations(bindings, 1_000);
    const message = dispatchMessageSchema.parse(producer.sent[0]?.body);

    await expect(dispatchOne(bindings, message, 2_000)).rejects.toThrow();
    await expect(
      env.DB.prepare("SELECT attempt_id FROM reconciliation_deliveries").first("attempt_id"),
    ).resolves.toBeNull();
    await expect(dispatchOne(bindings, message, 3_000)).resolves.toBe(true);
    expect(dispatches).toBe(1);
  });

  it("quarantines an ambiguous workflow-send failure", async () => {
    let dispatches = 0;
    server.use(
      http.post("https://api.github.com/app/installations/123/access_tokens", () =>
        HttpResponse.json({ token: "installation-token" }, { status: 201 }),
      ),
      http.get("https://api.github.com/repositories/9", () =>
        HttpResponse.json({ full_name: "owner/repo" }),
      ),
      http.post(
        "https://api.github.com/repos/owner/repo/actions/workflows/monitor.yaml/dispatches",
        () => {
          dispatches += 1;
          return HttpResponse.error();
        },
      ),
    );
    const producer = recordingQueue();
    const bindings = {
      DB: env.DB,
      GH_APP_ID: "42",
      GH_APP_INSTALLATION_ID: "123",
      GH_APP_PRIVATE_KEY: privateKey,
      FINDING_DISPATCH: producer.queue,
    };
    await enqueueReconciliations(bindings, 1_000);
    const message = dispatchMessageSchema.parse(producer.sent[0]?.body);

    await expect(dispatchOne(bindings, message, 2_000)).rejects.toThrow();
    await expect(
      env.DB.prepare("SELECT error FROM reconciliation_deliveries").first("error"),
    ).resolves.toBe("workflow dispatch outcome unknown");
    await expect(dispatchOne(bindings, message, 3_000)).rejects.toThrow(
      "reconciliation claim is already processing",
    );
    expect(dispatches).toBe(1);
  });
});
