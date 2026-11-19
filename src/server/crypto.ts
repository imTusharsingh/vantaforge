const ITERATIONS = 120_000;
const encoder = new TextEncoder();

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function bytesToBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function encryptionKeyBytes(value: string): Uint8Array {
  const trimmed = value.trim();
  try { const decoded = base64ToBytes(trimmed); if (decoded.byteLength === 32) return decoded; } catch { /* Try hex below. */ }
  if (/^[0-9a-f]{64}$/i.test(trimmed)) {
    const bytes = new Uint8Array(32);
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(trimmed.slice(index * 2, index * 2 + 2), 16);
    return bytes;
  }
  throw new Error("CREDENTIAL_ENCRYPTION_KEY must be a 32-byte base64 or 64-character hex secret");
}

export async function encryptSecret(secret: string, configuredKey: string | undefined): Promise<string> {
  if (!configuredKey) throw new Error("CREDENTIAL_ENCRYPTION_KEY is not configured");
  const key = await crypto.subtle.importKey("raw", bytesToBuffer(encryptionKeyBytes(configuredKey)), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret)));
  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength); combined.set(iv); combined.set(ciphertext, iv.byteLength);
  return bytesToBase64(combined);
}

export async function decryptSecret(encrypted: string, configuredKey: string | undefined): Promise<string> {
  if (!configuredKey) throw new Error("CREDENTIAL_ENCRYPTION_KEY is not configured");
  const combined = base64ToBytes(encrypted); if (combined.byteLength <= 12) throw new Error("Encrypted credential is invalid");
  const key = await crypto.subtle.importKey("raw", bytesToBuffer(encryptionKeyBytes(configuredKey)), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: combined.slice(0, 12) }, key, bytesToBuffer(combined.slice(12)));
  return new TextDecoder().decode(plaintext);
}

export function randomId(): string {
  return crypto.randomUUID();
}

export function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return bytesToBase64(new Uint8Array(digest));
}

export async function hashPassword(value: string): Promise<{ hash: string; salt: string }> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(value), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: saltBytes, iterations: ITERATIONS, hash: "SHA-256" }, key, 256);
  return { hash: bytesToBase64(new Uint8Array(bits)), salt: bytesToBase64(saltBytes) };
}

export async function verifyPassword(value: string, hash: string, salt: string): Promise<boolean> {
  const saltBytes = base64ToBytes(salt) as Uint8Array<ArrayBuffer>;
  const key = await crypto.subtle.importKey("raw", encoder.encode(value), "PBKDF2", false, ["deriveBits"]);
  const saltBuffer = saltBytes.buffer.slice(saltBytes.byteOffset, saltBytes.byteOffset + saltBytes.byteLength) as ArrayBuffer;
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: saltBuffer, iterations: ITERATIONS, hash: "SHA-256" }, key, 256);
  return constantTimeEqual(bytesToBase64(new Uint8Array(bits)), hash);
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}
