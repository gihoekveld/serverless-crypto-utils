// --- Types ---

/**
 * Result type for operations that can succeed or fail
 */
export type TokenResult<T> = 
  | { success: true; data: T }
  | { success: false; error: { code: string; message: string; details?: any } };

/**
 * Error codes for token operations
 */
export enum TokenErrorCode {
  INVALID_FORMAT = 'INVALID_FORMAT',
  SIGNATURE_VERIFICATION_FAILED = 'SIGNATURE_VERIFICATION_FAILED',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  INVALID_JSON = 'INVALID_JSON',
  MISSING_EXPIRATION = 'MISSING_EXPIRATION',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED'
}

// --- Helper Functions ---

/**
 * Derives a cryptographic key for HMAC signature from a secret string
 * @param signingSecret - The secret string used for token signing
 * @returns Promise<CryptoKey> - HMAC-SHA256 key for signing/verification
 */
const deriveHmacSignatureKey = async (signingSecret: string) => {
  const textEncoder = new TextEncoder();
  return await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(signingSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
};

/**
 * Derives an AES-256-GCM encryption key from a secret string
 * @param encryptionSecret - The secret string used for payload encryption
 * @returns Promise<CryptoKey> - AES-256-GCM key for encryption/decryption
 */
const deriveAesEncryptionKey = async (encryptionSecret: string) => {
  const textEncoder = new TextEncoder();
  
  // Ensure we have exactly 32 bytes for AES-256
  // If secret is shorter, pad with zeros; if longer, truncate
  const keyBytes = new Uint8Array(32);
  const secretBytes = textEncoder.encode(encryptionSecret);
  
  // Copy available bytes, leaving rest as zeros
  const copyLength = Math.min(secretBytes.length, 32);
  keyBytes.set(secretBytes.subarray(0, copyLength));
  
  return await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    true,
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

// --- Core Cryptographic Functions ---

/**
 * Encrypts payload data using AES-256-GCM algorithm
 * @param encryptionSecret - Secret key for encryption
 * @param payloadText - Plain text payload to encrypt
 * @returns Promise<string> - Encrypted data in format "iv.encryptedData" (both Base64)
 */
const encryptTokenPayload = async ({
  encryptionSecret,
  payloadText,
}: {
  encryptionSecret: string;
  payloadText: string;
}): Promise<string> => {
  // Generate random 12-byte initialization vector for AES-GCM
  const initializationVector = crypto.getRandomValues(new Uint8Array(12));
  const textEncoder = new TextEncoder();
  const encryptionKey = await deriveAesEncryptionKey(encryptionSecret);

  // Encrypt the payload using AES-GCM
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: initializationVector },
    encryptionKey,
    textEncoder.encode(payloadText)
  );

  const ivBase64 = convertBytesToBase64(initializationVector);
  const encryptedDataBase64 = convertBytesToBase64(new Uint8Array(encryptedBuffer));

  return `${ivBase64}.${encryptedDataBase64}`;
};

/**
 * Decrypts encrypted payload data using AES-256-GCM algorithm
 * @param encryptionSecret - Secret key for decryption
 * @param ivBase64 - Base64 encoded initialization vector
 * @param encryptedDataBase64 - Base64 encoded encrypted data
 * @returns Promise<string> - Decrypted plain text payload
 */
const decryptTokenPayload = async ({
  encryptionSecret,
  ivBase64,
  encryptedDataBase64,
}: {
  encryptionSecret: string;
  ivBase64: string;
  encryptedDataBase64: string;
}): Promise<string> => {
  const decryptionKey = await deriveAesEncryptionKey(encryptionSecret);
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
};

/**
 * Create a secure access token with encrypted payload and HMAC signature.
 *
 * @param {Object} options - Options for token creation
 * @param {string} options.encryptionSecret - Secret used to encrypt the payload (AES-GCM)
 * @param {string} options.signingSecret - Secret used to sign the payload (HMAC-SHA256)
 * @param {Object} options.payload - JSON-serializable payload to include in the token
 * @param {number} [options.expiresInSeconds=3600] - Token expiration time in seconds (default: 1 hour)
 * @returns {Promise<string>} Access token in the format: ivBase64.cipherBase64.signatureBase64
 * @example
 * const token = await createAccessToken({
 *   encryptionSecret: "myEncryptionSecret",
 *   signingSecret: "mySigningSecret",
 *   payload: JSON.stringify({ userId: 123, expiresAt: new Date(Date.now() + 3600_000) })
 * });
 * console.log(token);
 */
export async function createAccessToken({
  encryptionSecret,
  signingSecret,
  payload,
  expiresInSeconds = 3600,
}: {
  encryptionSecret: string;
  signingSecret: string;
  payload: Record<string, any>;
  expiresInSeconds?: number;
}): Promise<string> {
  // Add expiration timestamp to the payload
  const expirationTimestamp = new Date(Date.now() + expiresInSeconds * 1000);
  const payloadWithExpiration = {
    ...payload,
    expiresAt: expirationTimestamp.toISOString(),
  };

  const payloadJsonString = JSON.stringify(payloadWithExpiration);

  // Create HMAC signature key for token validation
  const textEncoder = new TextEncoder();
  const hmacSignatureKey = await deriveHmacSignatureKey(signingSecret);

  // Encrypt the payload data
  const encryptedPayloadData = await encryptTokenPayload({
    encryptionSecret,
    payloadText: payloadJsonString,
  });

  // Sign the original payload (before encryption) for integrity verification
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    hmacSignatureKey,
    textEncoder.encode(payloadJsonString)
  );

  const signatureBase64 = btoa(
    String.fromCharCode(...new Uint8Array(signatureBuffer))
  );

  // Return token in format: "iv.encryptedData.signature"
  return `${encryptedPayloadData}.${signatureBase64}`;
}

/**
 * Verify an access token, decrypt the payload, and validate signature and expiration.
 * This version returns a Result type instead of throwing exceptions.
 *
 * @param options - Options for token verification
 * @returns Promise<TokenResult<string>> - Result containing either the decrypted payload or error details
 * @example
 * const result = await verifyAccessTokenSafe({
 *   encryptionSecret: "myEncryptionSecret",
 *   signingSecret: "mySigningSecret",
 *   accessToken: "ivBase64.encryptedData.signature"
 * });
 * 
 * if (result.success) {
 *   const data = JSON.parse(result.data);
 *   console.log(data.userId);
 * } else {
 *   console.error(`Error ${result.error.code}: ${result.error.message}`);
 * }
 */
export async function verifyAccessTokenSafe({
  encryptionSecret,
  signingSecret,
  accessToken,
}: {
  encryptionSecret: string;
  signingSecret: string;
  accessToken: string;
}): Promise<TokenResult<string>> {
  try {
    const textEncoder = new TextEncoder();
    const hmacVerificationKey = await deriveHmacSignatureKey(signingSecret);

    // Parse token parts: iv.encryptedData.signature
    const tokenParts = accessToken.split(".");
    
    if (tokenParts.length !== 3) {
      return {
        success: false,
        error: {
          code: TokenErrorCode.INVALID_FORMAT,
          message: "Invalid access token format: expected 3 parts separated by dots",
          details: { partsFound: tokenParts.length, expected: 3 }
        }
      };
    }

    const [ivBase64, encryptedDataBase64, signatureBase64] = tokenParts;
    const signatureBytes = convertBase64ToBytes(signatureBase64);

    // Decrypt the payload to get the original data
    let decryptedPayloadString: string;
    try {
      decryptedPayloadString = await decryptTokenPayload({
        encryptionSecret,
        ivBase64,
        encryptedDataBase64,
      });
    } catch (error) {
      return {
        success: false,
        error: {
          code: TokenErrorCode.DECRYPTION_FAILED,
          message: "Failed to decrypt token payload",
          details: { originalError: error instanceof Error ? error.message : String(error) }
        }
      };
    }

    // Verify HMAC signature against the original payload
    const isSignatureValid = await crypto.subtle.verify(
      "HMAC",
      hmacVerificationKey,
      signatureBytes,
      textEncoder.encode(decryptedPayloadString)
    );

    if (!isSignatureValid) {
      return {
        success: false,
        error: {
          code: TokenErrorCode.SIGNATURE_VERIFICATION_FAILED,
          message: "Token signature verification failed"
        }
      };
    }

    // Parse and validate token expiration
    let parsedPayload;
    try {
      parsedPayload = JSON.parse(decryptedPayloadString);
    } catch {
      return {
        success: false,
        error: {
          code: TokenErrorCode.INVALID_JSON,
          message: "Token payload is not valid JSON"
        }
      };
    }

    const expirationTimestamp = parsedPayload?.expiresAt;

    if (!expirationTimestamp) {
      return {
        success: false,
        error: {
          code: TokenErrorCode.MISSING_EXPIRATION,
          message: "Token payload missing expiration timestamp"
        }
      };
    }

    const currentTimestamp = Date.now();
    const tokenExpirationTime = new Date(expirationTimestamp).getTime();

    if (currentTimestamp > tokenExpirationTime) {
      return {
        success: false,
        error: {
          code: TokenErrorCode.TOKEN_EXPIRED,
          message: "Access token has expired",
          details: { 
            expiredAt: expirationTimestamp,
            currentTime: new Date(currentTimestamp).toISOString()
          }
        }
      };
    }

    return {
      success: true,
      data: decryptedPayloadString
    };

  } catch (error) {
    return {
      success: false,
      error: {
        code: TokenErrorCode.ENCRYPTION_FAILED,
        message: "Unexpected error during token verification",
        details: { originalError: error instanceof Error ? error.message : String(error) }
      }
    };
  }
}

/**
 * Verify an access token, decrypt the payload, and validate signature and expiration.
 *
 * @param {Object} options - Options for token verification
 * @param {string} options.encryptionSecret - Secret used to encrypt the payload (AES-GCM)
 * @param {string} options.signingSecret - Secret used to sign the payload (HMAC-SHA256)
 * @param {string} options.token - The access token to verify
 * @returns {Promise<string>} The decrypted payload as a JSON string
 * @throws {Error} If token signature is invalid or token has expired
 * @example
 * const payload = await verifyAccessToken({
 *   encryptionSecret: "myEncryptionSecret",
 *   signingSecret: "mySigningSecret",
 *   token: "ivBase64.cipherBase64.signatureBase64"
 * });
 * const data = JSON.parse(payload);
 * console.log(data.userId);
 */
export async function verifyAccessToken({
  encryptionSecret,
  signingSecret,
  accessToken,
}: {
  encryptionSecret: string;
  signingSecret: string;
  accessToken: string;
}): Promise<string> {
  const textEncoder = new TextEncoder();
  const hmacVerificationKey = await deriveHmacSignatureKey(signingSecret);

  // Parse token parts: iv.encryptedData.signature
  const [ivBase64, encryptedDataBase64, signatureBase64] = accessToken.split(".");
  
  if (!ivBase64 || !encryptedDataBase64 || !signatureBase64) {
    throw new Error("Invalid access token format: expected 3 parts separated by dots");
  }

  const signatureBytes = convertBase64ToBytes(signatureBase64);

  // Decrypt the payload to get the original data
  const decryptedPayloadString = await decryptTokenPayload({
    encryptionSecret,
    ivBase64,
    encryptedDataBase64,
  });

  // Verify HMAC signature against the original payload
  const isSignatureValid = await crypto.subtle.verify(
    "HMAC",
    hmacVerificationKey,
    signatureBytes,
    textEncoder.encode(decryptedPayloadString)
  );

  if (!isSignatureValid) {
    throw new Error("Invalid access token: signature verification failed");
  }

  // Parse and validate token expiration
  let parsedPayload;
  try {
    parsedPayload = JSON.parse(decryptedPayloadString);
  } catch {
    throw new Error("Invalid access token: payload is not valid JSON");
  }

  const expirationTimestamp = parsedPayload?.expiresAt;

  if (!expirationTimestamp) {
    throw new Error("Invalid access token: missing expiration timestamp");
  }

  const currentTimestamp = Date.now();
  const tokenExpirationTime = new Date(expirationTimestamp).getTime();

  if (currentTimestamp > tokenExpirationTime) {
    throw new Error("Access token has expired");
  }

  return decryptedPayloadString;
}
