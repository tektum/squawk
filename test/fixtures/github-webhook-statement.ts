export const AMD64_DIGEST = `sha256:${"a".repeat(64)}`;
export const INDEX_DIGEST = `sha256:${"b".repeat(64)}`;
export const ARM64_DIGEST = `sha256:${"c".repeat(64)}`;

type StatementOptions = {
  readonly componentName?: string;
  readonly componentVersion?: string;
  readonly indexOnly?: boolean;
  readonly invalidPredicate?: boolean;
  readonly wrongSubject?: boolean;
};

export function statement(
  platform: "amd64" | "arm64",
  digest: string,
  options: StatementOptions = {},
) {
  const rootId = `SPDXRef-${platform}`;
  const componentName = options.componentName ?? "demo";
  const componentVersion = options.componentVersion ?? "1.5.0";
  return {
    _type: "https://in-toto.io/Statement/v0.1",
    subject: [
      {
        name: "ghcr.io/owner/demo",
        digest: { sha256: (options.wrongSubject ? AMD64_DIGEST : INDEX_DIGEST).slice(7) },
      },
    ],
    predicateType: "https://spdx.dev/Document",
    predicate: options.invalidPredicate
      ? { spdxVersion: "SPDX-2.3", packages: [] }
      : {
          spdxVersion: "SPDX-2.3",
          documentDescribes: [rootId],
          packages: [
            {
              SPDXID: rootId,
              name: `demo-${platform}`,
              versionInfo: digest,
              externalRefs: [
                {
                  referenceType: "purl",
                  referenceLocator: options.indexOnly
                    ? `pkg:oci/demo@${INDEX_DIGEST}?mediaType=application%2Fvnd.oci.image.index.v1%2Bjson`
                    : `pkg:oci/demo@${digest}?arch=${platform}&os=linux`,
                },
              ],
            },
            {
              SPDXID: `SPDXRef-component-${platform}`,
              name: componentName,
              versionInfo: componentVersion,
              externalRefs: [
                {
                  referenceType: "purl",
                  referenceLocator: `pkg:npm/${componentName}@${componentVersion}`,
                },
              ],
            },
          ],
        },
  };
}
