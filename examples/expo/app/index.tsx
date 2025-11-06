import { useEffect, useState } from "react";
import { Button, Text, TextInput, View } from "react-native";
import { authClient } from "../lib/auth-client";

export default function Home() {
  const { data: session, isPending, refetch } = authClient.useSession();
  const [email, setEmail] = useState("expo@example.com");
  const [password, setPassword] = useState("password123");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    void refetch();
  }, [refetch]);

  return (
    <View style={{ flex: 1, justifyContent: "center", padding: 24, gap: 8 }}>
      <Text style={{ fontSize: 22, fontWeight: "600" }}>Expo + Better Auth (Go)</Text>
      <Text>Bearer token auth for mobile — enable plugins.Bearer on the server.</Text>
      {isPending ? (
        <Text>Loading session…</Text>
      ) : session ? (
        <Text>Signed in as {session.user.email}</Text>
      ) : (
        <Text>Not signed in</Text>
      )}
      <TextInput value={email} onChangeText={setEmail} placeholder="Email" autoCapitalize="none" />
      <TextInput value={password} onChangeText={setPassword} placeholder="Password" secureTextEntry />
      <Button
        title="Sign in"
        onPress={async () => {
          const { error } = await authClient.signIn.email({ email, password });
          setMessage(error ? (error.message ?? "Failed") : "Signed in");
          await refetch();
        }}
      />
      <Button
        title="Sign out"
        onPress={async () => {
          await authClient.signOut();
          setMessage("Signed out");
          await refetch();
        }}
      />
      {message ? <Text>{message}</Text> : null}
    </View>
  );
}
