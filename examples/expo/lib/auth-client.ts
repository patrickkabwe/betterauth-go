import { createAuthClient } from "better-auth/client";
import { organizationClient, usernameClient } from "better-auth/client/plugins";
import * as SecureStore from "expo-secure-store";
import { Platform } from "react-native";

const baseURL = process.env.EXPO_PUBLIC_AUTH_URL ?? "http://localhost:8080";
const TOKEN_KEY = "better-auth.bearer-token";

async function getToken(): Promise<string | undefined> {
  if (Platform.OS === "web") {
    return sessionStorage.getItem(TOKEN_KEY) ?? undefined;
  }
  return (await SecureStore.getItemAsync(TOKEN_KEY)) ?? undefined;
}

async function setToken(token: string) {
  if (Platform.OS === "web") {
    sessionStorage.setItem(TOKEN_KEY, token);
    return;
  }
  await SecureStore.setItemAsync(TOKEN_KEY, token);
}

/**
 * Expo / React Native uses better-auth/client (not @better-auth/expo) with bearer tokens.
 * Enable plugins.Bearer on the Go server and persist set-auth-token from responses.
 */
export const authClient = createAuthClient({
  baseURL,
  fetchOptions: {
    onSuccess: async (ctx) => {
      const token = ctx.response.headers.get("set-auth-token");
      if (token) await setToken(token);
    },
    auth: {
      type: "Bearer",
      token: () => getToken(),
    },
  },
  plugins: [usernameClient(), organizationClient()],
});
