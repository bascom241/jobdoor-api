export function reportError(operation: string, error: unknown): void {
  // Error payloads may contain credentials or email tokens.
  console.error(operation, error instanceof Error ? error.name : 'UnknownError');
}
