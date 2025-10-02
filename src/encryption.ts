// --- Types ---

/**
 * Result type for operations that can succeed or fail
 */
export type EncryptionResult<T> = 
  | { success: true; data: T }
  | { success: false; error: { code: string; message: string; details?: any } };

/**
 * Error codes for encryption operations
 */
export enum EncryptionErrorCode {
  INVALID_FORMAT = 'INVALID_FORMAT',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  INVALID_JSON = 'INVALID_JSON',
  INVALID_SECRET = 'INVALID_SECRET'
}

// --- Helper Functions ---

/**
 * Derives an AES-256-GCM encryption key from a secret string
 * @param secret - The secret string used for encryption/decryption
 * @returns Promise<CryptoKey> - AES-256-GCM key for encryption/decryption
 */
const deriveEncryptionKey = async (secret: string): Promise<CryptoKey> => {
  if (!secret || secret.length === 0) {
    throw new Error("Encryption secret cannot be empty");
  }

  const textEncoder = new TextEncoder();
  
  // Ensure we have exactly 32 bytes for AES-256
  // If secret is shorter, pad with zeros; if longer, truncate
  const keyBytes = new Uint8Array(32);
  const secretBytes = textEncoder.encode(secret);
  
  // Copy available bytes, leaving rest as zeros
  const copyLength = Math.min(secretBytes.length, 32);
  keyBytes.set(secretBytes.subarray(0, copyLength));
  
  return await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
};

/**
 * Converts a Base64 string to Uint8Array for cryptographic operations
 * @param base64String - Base64 encoded string to convert
 * @returns Uint8Array representation of the decoded data
 */
const convertBase64ToBytes = (base64String: string): Uint8Array<ArrayBuffer> => {
  const binaryString = atob(base64String);
  const byteArray = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    byteArray[i] = binaryString.charCodeAt(i);
  }
  return byteArray;
};

/**
 * Converts a Uint8Array to Base64 string for safe transport/storage
 * @param byteArray - Uint8Array to convert
 * @returns Base64 encoded string
 */
const convertBytesToBase64 = (byteArray: Uint8Array): string => {
  return btoa(String.fromCharCode(...byteArray));
};

// --- Core Encryption Functions ---

/**
 * Encrypts a string using AES-256-GCM algorithm
 * 
 * @param data - The plain text string to encrypt
 * @param secret - The secret key for encryption (any length, will be normalized to 32 bytes)
 * @returns Promise<string> - Encrypted data in format "iv.encryptedData" (both Base64)
 * @example
 * const encrypted = await encrypt("sensitive data", "mySecretKey");
 * console.log(encrypted); // "ivBase64.encryptedDataBase64"
 */
export async function encrypt(data: string, secret: string): Promise<string> {
  if (!data) {
    throw new Error("Data to encrypt cannot be empty");
  }

  // Generate random 12-byte initialization vector for AES-GCM
  const initializationVector = crypto.getRandomValues(new Uint8Array(12));
  const textEncoder = new TextEncoder();
  const encryptionKey = await deriveEncryptionKey(secret);

  // Encrypt the data using AES-GCM
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: initializationVector },
    encryptionKey,
    textEncoder.encode(data)
  );

  const ivBase64 = convertBytesToBase64(initializationVector);
  const encryptedDataBase64 = convertBytesToBase64(new Uint8Array(encryptedBuffer));

  return `${ivBase64}.${encryptedDataBase64}`;
}

/**
 * Decrypts a string that was encrypted with the encrypt function
 * 
 * @param encryptedData - The encrypted data in format "iv.encryptedData" (both Base64)
 * @param secret - The secret key used for encryption
 * @returns Promise<string> - The decrypted plain text string
 * @example
 * const decrypted = await decrypt("ivBase64.encryptedDataBase64", "mySecretKey");
 * console.log(decrypted); // "sensitive data"
 */
export async function decrypt(encryptedData: string, secret: string): Promise<string> {
  if (!encryptedData) {
    throw new Error("Encrypted data cannot be empty");
  }

  // Parse encrypted data: iv.encryptedData
  const parts = encryptedData.split(".");
  
  if (parts.length !== 2) {
    throw new Error("Invalid encrypted data format: expected 2 parts separated by dot");
  }

  const [ivBase64, encryptedDataBase64] = parts;
  
  const decryptionKey = await deriveEncryptionKey(secret);
  const initializationVector = convertBase64ToBytes(ivBase64);
  const encryptedDataBytes = convertBase64ToBytes(encryptedDataBase64);

  // Decrypt the data using AES-GCM
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: initializationVector },
    decryptionKey,
    encryptedDataBytes
  );

  const textDecoder = new TextDecoder();
  return textDecoder.decode(decryptedBuffer);
}

/**
 * Encrypts an object by JSON-stringifying it and then encrypting the string
 * 
 * @param object - The object to encrypt
 * @param secret - The secret key for encryption
 * @returns Promise<string> - Encrypted data in format "iv.encryptedData" (both Base64)
 * @example
 * const user = { name: "John", email: "john@example.com", age: 30 };
 * const encrypted = await encryptObject(user, "mySecretKey");
 * console.log(encrypted); // "ivBase64.encryptedDataBase64"
 */
export async function encryptObject<T>(object: T, secret: string): Promise<string> {
  if (object === null || object === undefined) {
    throw new Error("Object to encrypt cannot be null or undefined");
  }

  const jsonString = JSON.stringify(object);
  return await encrypt(jsonString, secret);
}

/**
 * Decrypts an object that was encrypted with encryptObject
 * 
 * @param encryptedData - The encrypted data in format "iv.encryptedData" (both Base64)
 * @param secret - The secret key used for encryption
 * @returns Promise<T> - The decrypted object
 * @example
 * const decrypted = await decryptObject<User>("ivBase64.encryptedDataBase64", "mySecretKey");
 * console.log(decrypted); // { name: "John", email: "john@example.com", age: 30 }
 */
export async function decryptObject<T>(encryptedData: string, secret: string): Promise<T> {
  const decryptedString = await decrypt(encryptedData, secret);
  
  try {
    return JSON.parse(decryptedString) as T;
  } catch (error) {
    throw new Error("Failed to parse decrypted data as JSON: " + (error instanceof Error ? error.message : String(error)));
  }
}

// --- Safe Versions (Result Pattern) ---

/**
 * Safely encrypts a string using Result pattern (no exceptions)
 * 
 * @param data - The plain text string to encrypt
 * @param secret - The secret key for encryption
 * @returns Promise<EncryptionResult<string>> - Result containing either encrypted data or error details
 * @example
 * const result = await encryptSafe("sensitive data", "mySecretKey");
 * if (result.success) {
 *   console.log("Encrypted:", result.data);
 * } else {
 *   console.error("Error:", result.error.message);
 * }
 */
export async function encryptSafe(data: string, secret: string): Promise<EncryptionResult<string>> {
  try {
    const encrypted = await encrypt(data, secret);
    return { success: true, data: encrypted };
  } catch (error) {
    return {
      success: false,
      error: {
        code: EncryptionErrorCode.ENCRYPTION_FAILED,
        message: "Failed to encrypt data",
        details: { originalError: error instanceof Error ? error.message : String(error) }
      }
    };
  }
}

/**
 * Safely decrypts a string using Result pattern (no exceptions)
 * 
 * @param encryptedData - The encrypted data to decrypt
 * @param secret - The secret key used for encryption
 * @returns Promise<EncryptionResult<string>> - Result containing either decrypted data or error details
 * @example
 * const result = await decryptSafe("ivBase64.encryptedDataBase64", "mySecretKey");
 * if (result.success) {
 *   console.log("Decrypted:", result.data);
 * } else {
 *   console.error("Error:", result.error.message);
 * }
 */
export async function decryptSafe(encryptedData: string, secret: string): Promise<EncryptionResult<string>> {
  try {
    const decrypted = await decrypt(encryptedData, secret);
    return { success: true, data: decrypted };
  } catch (error) {
    return {
      success: false,
      error: {
        code: EncryptionErrorCode.DECRYPTION_FAILED,
        message: "Failed to decrypt data",
        details: { originalError: error instanceof Error ? error.message : String(error) }
      }
    };
  }
}

/**
 * Safely encrypts an object using Result pattern (no exceptions)
 * 
 * @param object - The object to encrypt
 * @param secret - The secret key for encryption
 * @returns Promise<EncryptionResult<string>> - Result containing either encrypted data or error details
 * @example
 * const user = { name: "John", email: "john@example.com" };
 * const result = await encryptObjectSafe(user, "mySecretKey");
 * if (result.success) {
 *   console.log("Encrypted:", result.data);
 * } else {
 *   console.error("Error:", result.error.message);
 * }
 */
export async function encryptObjectSafe<T>(object: T, secret: string): Promise<EncryptionResult<string>> {
  try {
    const encrypted = await encryptObject(object, secret);
    return { success: true, data: encrypted };
  } catch (error) {
    return {
      success: false,
      error: {
        code: EncryptionErrorCode.ENCRYPTION_FAILED,
        message: "Failed to encrypt object",
        details: { originalError: error instanceof Error ? error.message : String(error) }
      }
    };
  }
}

/**
 * Safely decrypts an object using Result pattern (no exceptions)
 * 
 * @param encryptedData - The encrypted data to decrypt
 * @param secret - The secret key used for encryption
 * @returns Promise<EncryptionResult<T>> - Result containing either decrypted object or error details
 * @example
 * const result = await decryptObjectSafe<User>("ivBase64.encryptedDataBase64", "mySecretKey");
 * if (result.success) {
 *   console.log("User:", result.data);
 * } else {
 *   console.error("Error:", result.error.message);
 * }
 */
export async function decryptObjectSafe<T>(encryptedData: string, secret: string): Promise<EncryptionResult<T>> {
  try {
    const decrypted = await decryptObject<T>(encryptedData, secret);
    return { success: true, data: decrypted };
  } catch (error) {
    return {
      success: false,
      error: {
        code: EncryptionErrorCode.DECRYPTION_FAILED,
        message: "Failed to decrypt object",
        details: { originalError: error instanceof Error ? error.message : String(error) }
      }
    };
  }
}