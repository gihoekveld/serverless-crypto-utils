# Encryption

_🇺🇸 English | [🇧🇷 Português](../pt-BR/encryption.md)_

Simple and secure data encryption using **AES-256-GCM** algorithm.

Designed for **Serverless/Edge** environments like Cloudflare Workers, with support for **string** and **object** encryption using only the Web Crypto API.

## 🔑 Main Functions

### String Encryption

#### `encrypt(data, secret)`

Encrypts a string using AES-256-GCM algorithm.

```typescript
import { encrypt } from "serverless-crypto-utils/encryption";

const encrypted = await encrypt("sensitive data", "mySecretKey");
console.log(encrypted); // "ivBase64.encryptedDataBase64"
```

| Parameter | Type   | Description                                                        |
| --------- | ------ | ------------------------------------------------------------------ |
| `data`    | string | The plain text string to encrypt                                   |
| `secret`  | string | The secret key for encryption (any length, normalized to 32 bytes) |

#### `decrypt(encryptedData, secret)`

Decrypts a string that was encrypted with the encrypt function.

```typescript
import { decrypt } from "serverless-crypto-utils/encryption";

const decrypted = await decrypt("ivBase64.encryptedDataBase64", "mySecretKey");
console.log(decrypted); // "sensitive data"
```

| Parameter       | Type   | Description                                              |
| --------------- | ------ | -------------------------------------------------------- |
| `encryptedData` | string | The encrypted data in format "iv.encryptedData" (Base64) |
| `secret`        | string | The secret key used for encryption                       |

### Object Encryption

#### `encryptObject<T>(object, secret)`

Encrypts an object by JSON-stringifying it and then encrypting the string.

```typescript
import { encryptObject } from "serverless-crypto-utils/encryption";

const user = { name: "John", email: "john@example.com", age: 30 };
const encrypted = await encryptObject(user, "mySecretKey");
console.log(encrypted); // "ivBase64.encryptedDataBase64"
```

| Parameter | Type   | Description                   |
| --------- | ------ | ----------------------------- |
| `object`  | T      | The object to encrypt         |
| `secret`  | string | The secret key for encryption |

#### `decryptObject<T>(encryptedData, secret)`

Decrypts an object that was encrypted with encryptObject.

```typescript
import { decryptObject } from "serverless-crypto-utils/encryption";

type User = { name: string; email: string; age: number };
const decrypted = await decryptObject<User>(
  "ivBase64.encryptedDataBase64",
  "mySecretKey"
);
console.log(decrypted); // { name: "John", email: "john@example.com", age: 30 }
```

| Parameter       | Type   | Description                                              |
| --------------- | ------ | -------------------------------------------------------- |
| `encryptedData` | string | The encrypted data in format "iv.encryptedData" (Base64) |
| `secret`        | string | The secret key used for encryption                       |

## 🛡️ Safe Versions (Result Pattern)

All functions have "Safe" versions that use the Result pattern instead of throwing exceptions:

```typescript
import {
  encryptSafe,
  decryptSafe,
  encryptObjectSafe,
  decryptObjectSafe,
  EncryptionErrorCode,
} from "serverless-crypto-utils/encryption";

const result = await encryptSafe("sensitive data", "mySecretKey");
if (result.success) {
  console.log("Encrypted:", result.data);
} else {
  console.error(`Error ${result.error.code}: ${result.error.message}`);
}
```

**Error Codes:**

- `INVALID_FORMAT` - Malformed encrypted data
- `ENCRYPTION_FAILED` - Encryption operation failed
- `DECRYPTION_FAILED` - Decryption operation failed
- `INVALID_JSON` - Object decryption failed (invalid JSON)
- `INVALID_SECRET` - Invalid or empty secret provided

## 🔒 Security Features

- **AES-256-GCM encryption** for confidentiality and integrity
- **Unique random IV** per encryption (12 bytes)
- **Flexible secret handling** (any length, normalized to 32 bytes)
- **Web Crypto API** for cryptographically secure operations
- **No external dependencies** for minimal attack surface

## 📌 Complete Examples

### Basic String Encryption

```typescript
import { encrypt, decrypt } from "serverless-crypto-utils/encryption";

const secret = process.env.ENCRYPTION_SECRET || "mySecretKey";

// Encrypt sensitive data
const sensitiveData = "User's credit card: 4532 1234 5678 9012";
const encrypted = await encrypt(sensitiveData, secret);

// Store encrypted data in database
await database.store({ id: "user-123", encryptedData: encrypted });

// Later, retrieve and decrypt
const record = await database.get("user-123");
const decrypted = await decrypt(record.encryptedData, secret);
console.log(decrypted); // "User's credit card: 4532 1234 5678 9012"
```

### Object Encryption with TypeScript

```typescript
import {
  encryptObject,
  decryptObject,
} from "serverless-crypto-utils/encryption";

interface UserProfile {
  id: number;
  name: string;
  email: string;
  preferences: {
    theme: string;
    notifications: boolean;
  };
}

const secret = process.env.ENCRYPTION_SECRET;

// Encrypt user profile
const profile: UserProfile = {
  id: 123,
  name: "John Doe",
  email: "john@example.com",
  preferences: {
    theme: "dark",
    notifications: true,
  },
};

const encryptedProfile = await encryptObject(profile, secret);

// Store in database
await database.updateUser(123, { encryptedProfile });

// Later, retrieve and decrypt
const user = await database.getUser(123);
const decryptedProfile = await decryptObject<UserProfile>(
  user.encryptedProfile,
  secret
);
console.log(decryptedProfile.name); // "John Doe"
```

### Safe Operations with Error Handling

```typescript
import {
  encryptObjectSafe,
  decryptObjectSafe,
  EncryptionErrorCode,
} from "serverless-crypto-utils/encryption";

async function securelyStoreUserData(userId: string, userData: any) {
  const secret = process.env.ENCRYPTION_SECRET;

  const result = await encryptObjectSafe(userData, secret);

  if (!result.success) {
    console.error(`Encryption failed: ${result.error.message}`);
    throw new Error("Failed to secure user data");
  }

  await database.store({ userId, encryptedData: result.data });
  return true;
}

async function retrieveUserData(userId: string) {
  const secret = process.env.ENCRYPTION_SECRET;
  const record = await database.get(userId);

  const result = await decryptObjectSafe(record.encryptedData, secret);

  if (!result.success) {
    if (result.error.code === EncryptionErrorCode.DECRYPTION_FAILED) {
      console.error("Invalid encryption key or corrupted data");
    }
    return null;
  }

  return result.data;
}
```

## 🔍 Use Cases

### When to use:

- **Personal Identifiable Information (PII)** encryption
- **Sensitive user preferences** storage
- **API keys and tokens** storage
- **Credit card or payment information** encryption
- **Medical or legal documents** encryption
- **Temporary sensitive data** caching

### When NOT to use:

- **Passwords** (use `password-hashing` module instead)
- **Large files** (consider streaming encryption)
- **Real-time communication** (high latency overhead)
- **Public data** that doesn't need protection
