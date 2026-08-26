import { z } from "zod";
import { request } from "./descope-request";

const permissionSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
});
const rolesSchema = z.object({
  roles: z.array(
    z.object({
      name: z.string(),
      description: z.string().nullish(),
      permissionNames: z.array(z.string()).nullish(),
      tenantId: z.string().nullish(),
    }),
  ),
});
const permissionsSchema = z.object({
  permissions: z.array(z.object({ name: z.string(), description: z.string().nullish() })),
});

export const authorizationSchema = z.object({
  tenantId: z.string().min(1),
  role: z.object({ name: z.string().min(1), description: z.string().min(1) }),
  permissions: z.array(permissionSchema).min(1),
});

export type AuthorizationChange =
  | "permission:create"
  | "permission:update"
  | "role:create"
  | "role:update";

/* Session JWTs carry `tenants[t].permissions` from project permissions attached to a
   tenant role, which is a different surface from the inbound application scopes the
   rest of provisioning reconciles. Without both, a human authenticates and is then
   refused every capability. Assigning the role to a person stays a console decision:
   provisioning never touches user records. */
export async function reconcileAuthorization(
  baseUrl: string,
  authorization: string,
  desired: z.infer<typeof authorizationSchema>,
): Promise<readonly AuthorizationChange[]> {
  const changes: AuthorizationChange[] = [];
  const loaded = await request(new URL("/v1/mgmt/permission/all", baseUrl), authorization);
  if (!loaded.ok) throw new Error(`Descope permission list failed (${loaded.status})`);
  const existing = new Map(
    permissionsSchema
      .parse(await loaded.json())
      .permissions.map((permission) => [permission.name, permission.description ?? ""]),
  );
  for (const permission of desired.permissions) {
    const current = existing.get(permission.name);
    if (current === permission.description) continue;
    const create = current === undefined;
    const response = await request(
      new URL(`/v1/mgmt/permission/${create ? "create" : "update"}`, baseUrl),
      authorization,
      {
        method: "POST",
        body: JSON.stringify(create ? permission : { ...permission, newName: permission.name }),
      },
    );
    if (!response.ok)
      throw new Error(
        `Descope permission ${create ? "create" : "update"} failed (${response.status})`,
      );
    changes.push(create ? "permission:create" : "permission:update");
  }
  return [...changes, ...(await reconcileRole(baseUrl, authorization, desired))];
}

async function reconcileRole(
  baseUrl: string,
  authorization: string,
  desired: z.infer<typeof authorizationSchema>,
): Promise<readonly AuthorizationChange[]> {
  const permissionNames = desired.permissions.map((permission) => permission.name);
  const loaded = await request(new URL("/v1/mgmt/role/all", baseUrl), authorization);
  if (!loaded.ok) throw new Error(`Descope role list failed (${loaded.status})`);
  const role = rolesSchema
    .parse(await loaded.json())
    .roles.find(
      (candidate) =>
        candidate.name === desired.role.name && (candidate.tenantId ?? "") === desired.tenantId,
    );
  const body = {
    name: desired.role.name,
    description: desired.role.description,
    permissionNames,
    tenantId: desired.tenantId,
  };
  if (
    role &&
    (role.description ?? "") === desired.role.description &&
    JSON.stringify([...(role.permissionNames ?? [])].sort()) ===
      JSON.stringify([...permissionNames].sort())
  )
    return [];
  const response = await request(
    new URL(`/v1/mgmt/role/${role ? "update" : "create"}`, baseUrl),
    authorization,
    { method: "POST", body: JSON.stringify(role ? { ...body, newName: desired.role.name } : body) },
  );
  if (!response.ok)
    throw new Error(`Descope role ${role ? "update" : "create"} failed (${response.status})`);
  return [role ? "role:update" : "role:create"];
}
