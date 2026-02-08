/**
 * Wallet encryption utilities using AES-GCM with PBKDF2 key derivation.
 * Uses Web Crypto API available in Cloudflare Workers.
 */

const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

/**
 * Derive an AES-GCM key from the master encryption key and a per-wallet salt.
 */
async function deriveKey(masterKey: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(masterKey),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt a JWK object.
 * Returns { encrypted: base64, salt: base64 }
 */
export async function encryptJwk(
  jwk: JsonWebKey,
  masterKey: string
): Promise<{ encrypted: string; salt: string }> {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(masterKey, salt);

  const plaintext = encoder.encode(JSON.stringify(jwk));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );

  // Prepend IV to ciphertext
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return {
    encrypted: btoa(String.fromCharCode(...combined)),
    salt: btoa(String.fromCharCode(...salt)),
  };
}

/**
 * Decrypt an encrypted JWK.
 */
export async function decryptJwk(
  encrypted: string,
  salt: string,
  masterKey: string
): Promise<JsonWebKey> {
  const combined = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));
  const saltBytes = Uint8Array.from(atob(salt), (c) => c.charCodeAt(0));

  const iv = combined.slice(0, IV_LENGTH);
  const ciphertext = combined.slice(IV_LENGTH);

  const key = await deriveKey(masterKey, saltBytes);

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(plaintext)) as JsonWebKey;
}
