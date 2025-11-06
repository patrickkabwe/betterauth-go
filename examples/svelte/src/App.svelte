<script lang="ts">
  import { authClient } from "./lib/auth-client";

  const session = authClient.useSession();
  let email = $state("svelte@example.com");
  let password = $state("password123");
  let message = $state<string | null>(null);

  async function signIn() {
    const { error } = await authClient.signIn.email({ email, password });
    message = error ? (error.message ?? "Sign in failed") : "Signed in";
  }

  async function signOut() {
    await authClient.signOut();
    message = "Signed out";
  }
</script>

<main style="font-family: system-ui; max-width: 32rem; margin: 2rem auto; padding: 1rem">
  <p style="opacity: 0.7">better-auth/svelte → Go server</p>
  <h1>Svelte client example</h1>
  {#if $session.isPending}
    <p>Loading session…</p>
  {:else if $session.data}
    <p>Hello, {$session.data.user.email}</p>
  {:else}
    <p>Not signed in</p>
  {/if}
  <form onsubmit={(e) => { e.preventDefault(); signIn(); }} style="display: grid; gap: 0.5rem; margin-top: 1rem">
    <input bind:value={email} type="email" placeholder="Email" required />
    <input bind:value={password} type="password" placeholder="Password" required />
    <button type="submit">Sign in</button>
    <button type="button" onclick={signOut}>Sign out</button>
  </form>
  {#if message}<p>{message}</p>{/if}
</main>
