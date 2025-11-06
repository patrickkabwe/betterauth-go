type AuthResult = { error?: { message?: string } | null; data?: unknown };

export function formatError(error: { message?: string } | null | undefined, fallback = "Request failed") {
  return error?.message ?? fallback;
}

export async function runAuthAction(
  action: () => Promise<AuthResult>,
  onMessage: (message: string, isError: boolean) => void,
  successMessage: string,
): Promise<boolean> {
  const { error } = await action();
  if (error) {
    onMessage(formatError(error), true);
    return false;
  }
  onMessage(successMessage, false);
  return true;
}

export function callbackURL() {
  return window.location.origin;
}
