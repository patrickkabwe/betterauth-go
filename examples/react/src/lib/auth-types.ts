/**
 * Server auth shape for inferAdditionalFields — keep in sync with Go auth.Config
 * or regenerate via: node ../../scripts/generate-client-types.mjs
 */
export type Auth = {
  user: {
    additionalFields: Record<string, never>;
  };
};
