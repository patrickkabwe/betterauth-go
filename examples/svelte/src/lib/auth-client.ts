import { createAuthClient } from "better-auth/svelte";
import { organizationClient, usernameClient } from "better-auth/client/plugins";

const baseURL = import.meta.env.VITE_AUTH_URL ?? "http://localhost:8080";

export const authClient = createAuthClient({
  baseURL,
  fetchOptions: {
    onSuccess(ctx) {
      const token = ctx.response.headers.get("set-auth-token");
      if (token) sessionStorage.setItem("better-auth.bearer-token", token);
    },
    auth: {
      type: "Bearer",
      token: () => sessionStorage.getItem("better-auth.bearer-token") ?? undefined,
    },
  },
  plugins: [usernameClient(), organizationClient()],
});
