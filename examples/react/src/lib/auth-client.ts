import { createAuthClient } from "better-auth/react";
import {
  anonymousClient,
  emailOTPClient,
  inferAdditionalFields,
  lastLoginMethodClient,
  magicLinkClient,
  organizationClient,
  twoFactorClient,
  usernameClient,
} from "better-auth/client/plugins";
import type { Auth } from "./auth-types";

export const baseURL = import.meta.env.VITE_AUTH_URL ?? "http://localhost:8070";

/**
 * Client plugins mirror the Go server plugins in examples/basic.
 * inferAdditionalFields<Auth>() gives typed user fields on session/user APIs.
 */
export const authClient = createAuthClient({
  baseURL,
  fetchOptions: {
    onSuccess(ctx) {
      const token = ctx.response.headers.get("set-auth-token");
      if (token) {
        sessionStorage.setItem("better-auth.bearer-token", token);
      }
    },
    auth: {
      type: "Bearer",
      token: () => sessionStorage.getItem("better-auth.bearer-token") ?? undefined,
    },
  },
  plugins: [
    usernameClient(),
    organizationClient(),
    twoFactorClient(),
    anonymousClient(),
    magicLinkClient(),
    emailOTPClient(),
    lastLoginMethodClient(),
    inferAdditionalFields<Auth>(),
  ],
});

export const { signIn, signUp, signOut, useSession, getSession } = authClient;

export function getBearerToken() {
  return sessionStorage.getItem("better-auth.bearer-token");
}
