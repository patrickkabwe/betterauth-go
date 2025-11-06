<script setup lang="ts">
import { ref } from "vue";
import { authClient } from "./lib/auth-client";

const session = authClient.useSession();
const email = ref("vue@example.com");
const password = ref("password123");
const message = ref<string | null>(null);

async function signIn() {
  const { error } = await authClient.signIn.email({ email: email.value, password: password.value });
  message.value = error ? error.message ?? "Sign in failed" : "Signed in";
}

async function signOut() {
  await authClient.signOut();
  message.value = "Signed out";
}
</script>

<template>
  <main style="font-family: system-ui; max-width: 32rem; margin: 2rem auto; padding: 1rem">
    <p style="opacity: 0.7">better-auth/vue → Go server</p>
    <h1>Vue client example</h1>
    <p v-if="session.isPending">Loading session…</p>
    <p v-else-if="session.data">Hello, {{ session.data.user.email }}</p>
    <p v-else>Not signed in</p>
    <form @submit.prevent="signIn" style="display: grid; gap: 0.5rem; margin-top: 1rem">
      <input v-model="email" type="email" placeholder="Email" required />
      <input v-model="password" type="password" placeholder="Password" required />
      <button type="submit">Sign in</button>
      <button type="button" @click="signOut">Sign out</button>
    </form>
    <p v-if="message">{{ message }}</p>
  </main>
</template>
