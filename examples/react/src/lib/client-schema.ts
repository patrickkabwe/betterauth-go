export type ClientSchema = {
  appName: string;
  baseURL: string;
  basePath: string;
  features: {
    emailAndPassword: boolean;
    socialProviders: string[];
    bearer: boolean;
  };
  plugins: Array<{ id: string }>;
};

export async function fetchClientSchema(baseURL: string): Promise<ClientSchema | null> {
  try {
    const res = await fetch(`${baseURL}/api/auth/client-schema`);
    if (!res.ok) return null;
    return (await res.json()) as ClientSchema;
  } catch {
    return null;
  }
}
