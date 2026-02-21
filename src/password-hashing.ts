import { fromBase64Url, toBase64Url } from "./utils";

/**
 * Hash a password using PBKDF2 with HMAC-SHA256.
 *
 * @param {string} password - The password to hash
 * @param {{ pepper?: string, iterations?: number, saltInBase64Url?: string }} [options] - Optional parameters:
 * - pepper: An optional secret value appended to the password before hashing for extra security
 * - iterations: Number of PBKDF2 iterations (between 1000 and 1000000). Defaults to 100000 for Cloudflare Workers limit.
 * - saltInBase64Url: Optional salt in Base64URL format (if not provided, a random 16-byte salt will be generated)
 * @returns {Promise<string>} The hashed password in the format: iterations.salt.hash
 * @throws {Error} If the provided iterations value is less than 1000 or more than 1000000
 * @example
 * const hashed = await hashPassword("mySecretPassword", { pepper: "myPepper", iterations: 500000, saltInBase64Url: "randomSaltInBase64Url" });
 * console.log(hashed); // e.g. "500000.randomSaltInBase64Url.hashInBase64Url"
 */
export async function hashPassword(
  password: string,
  options: {
    pepper?: string;
    iterations?: number;
    saltInBase64Url?: string;
  } = {},
): Promise<string> {
  const enc = new TextEncoder();

  // Salt aleatório (16 bytes)
  const salt = options?.saltInBase64Url
    ? fromBase64Url(options.saltInBase64Url)
    : crypto.getRandomValues(new Uint8Array(16));

  const pepper = options?.pepper || "";

  // Importa a senha como key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password.concat(pepper)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  if (options?.iterations && options.iterations < 1000) {
    throw new Error("Iterations must be at least 1000");
  }

  if (options?.iterations && options.iterations > 1000000) {
    throw new Error("Iterations must be at most 1000000");
  }

  // Deriva bits com PBKDF2-HMAC-SHA256
  const iterations = options?.iterations || 100000; // ajustável
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );

  // Retorna string no formato: iterations.salt.hash
  return [iterations, toBase64Url(salt.buffer), toBase64Url(derivedBits)].join(
    ".",
  );
}

/**
 * Verify a password against a stored hash.
 *
 * @param {string} password - The password to verify
 * @param {string} stored - The stored hash in the format: iterations.salt.hash
 * @param {{ pepper?: string }} [options] - Optional parameters:
 * - pepper: The secret value that was appended to the password before hashing (if any)
 * @returns {Promise<boolean>} True if the password matches the stored hash, false otherwise
 * @example
 * const isValid = await verifyPassword("mySecretPassword", "500000.randomSaltInBase64Url.hashInBase64Url", { pepper: "myPepper" });
 * console.log(isValid); // true or false
 */
export async function verifyPassword(
  password: string,
  stored: string,
  options: {
    pepper?: string;
  } = {},
): Promise<boolean> {
  const [iterStr, saltB64, hashB64] = stored.split(".");
  const iterations = Number.parseInt(iterStr, 10);
  const salt = fromBase64Url(saltB64);
  const expectedHash = fromBase64Url(hashB64);
  const pepper = options?.pepper || "";

  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password.concat(pepper)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    expectedHash.length * 8,
  );

  const actualHash = new Uint8Array(derivedBits);

  // Comparação segura (timing-safe)
  if (actualHash.length !== expectedHash.length) return false;
  return actualHash.every((b, i) => b === expectedHash[i]);
}
