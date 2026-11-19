export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ValidationError("Request body must be an object");
  return value as Record<string, unknown>;
}

export function requiredString(value: unknown, field: string, max = 255): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > max) throw new ValidationError(`${field} is invalid`);
  return value.trim();
}

export function email(value: unknown): string {
  const normalized = requiredString(value, "email", 320).toLowerCase();
  if (!EMAIL_RE.test(normalized)) throw new ValidationError("email is invalid");
  return normalized;
}

export function password(value: unknown): string {
  if (typeof value !== "string" || value.length < 12 || value.length > 256) throw new ValidationError("password must be between 12 and 256 characters");
  return value;
}

export function slug(value: unknown): string {
  const normalized = requiredString(value, "slug", 80).toLowerCase();
  if (!SLUG_RE.test(normalized)) throw new ValidationError("slug is invalid");
  return normalized;
}

export class ValidationError extends Error {}
