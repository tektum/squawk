import { z } from "zod";

export const TenantIdSchema = z.string().min(1).brand<"TenantId">();
export const UserIdSchema = z.string().min(1).brand<"UserId">();
export const SbomIdSchema = z.string().uuid().brand<"SbomId">();
export type TenantId = z.infer<typeof TenantIdSchema>;
export type UserId = z.infer<typeof UserIdSchema>;
export type SbomId = z.infer<typeof SbomIdSchema>;

export const capabilityValues = ["sbom.write", "findings.read", "vex.write"] as const;
export const CapabilitySchema = z.enum(capabilityValues);
export type Capability = z.infer<typeof CapabilitySchema>;

export const VexStatusSchema = z.enum(["not_affected", "affected", "fixed", "under_investigation"]);
export type VexStatus = z.infer<typeof VexStatusSchema>;

export const vexInputSchema = z.object({
  package_name: z.string().min(1),
  ecosystem: z.string().min(1),
  vuln_id: z.string().min(1),
  status: VexStatusSchema,
  justification: z.string().min(1).max(4_000).optional(),
});

export type Principal = {
  readonly tenantId: TenantId;
  readonly userId: UserId | undefined;
  readonly capabilities: ReadonlySet<Capability>;
};

export type Component = {
  readonly packageName: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly purl: string;
  readonly matchable: boolean;
};
