# Access Token

_🇺🇸 English | [🇧🇷 Português](../pt-BR/access-token.md)_

Creation and verification of secure access tokens using **AES-256-GCM** for encryption and **HMAC-SHA256** for signing.

Designed for **Serverless/Edge** environments like Cloudflare Workers, with support for **encryption**, **signing**, and **automatic expiration**.

## 🔑 Main Functions

### `createAccessToken(options)`

Creates a secure access token with encrypted payload.

```typescript
import { createAccessToken } from "serverless-crypto-utils";

const token = await createAccessToken({
  encryptionSecret: "your-32-char-encryption-secret",
  signingSecret: "your-hmac-signing-secret",
  payload: {
    userId: 12345,
    username: "user",
    role: "admin",
  },
  expiresInSeconds: 3600, // optional, default: 3600 (1 hour)
});

console.log(token); // e.g. "ivBase64.encryptedDataBase64.signatureBase64"
```

| Parameter          | Type                | Description                                        |
| ------------------ | ------------------- | -------------------------------------------------- |
| `encryptionSecret` | string              | Secret for AES-256-GCM encryption (min. 32 chars)  |
| `signingSecret`    | string              | Secret for HMAC-SHA256 signature                   |
| `payload`          | Record<string, any> | JSON data to be encrypted in the token             |
| `expiresInSeconds` | number              | Expiration time in seconds. Default: 3600 (1 hour) |

### `verifyAccessToken(options)`

Verifies and decrypts an access token (throws exceptions).

```typescript
import { verifyAccessToken } from "serverless-crypto-utils";

try {
  const payloadJson = await verifyAccessToken({
    encryptionSecret: "your-32-char-encryption-secret",
    signingSecret: "your-hmac-signing-secret",
    accessToken: token,
  });

  const payload = JSON.parse(payloadJson);
  console.log("User:", payload.userId);
} catch (error) {
  console.error("Invalid token:", error.message);
}
```

| Parameter          | Type   | Description                                  |
| ------------------ | ------ | -------------------------------------------- |
| `encryptionSecret` | string | Secret used for encryption                   |
| `signingSecret`    | string | Secret used for signing                      |
| `accessToken`      | string | Token in format `iv.encryptedData.signature` |

### `verifyAccessTokenSafe(options)` (Recommended)

Verifies and decrypts a token using Result Pattern (no exceptions).

```typescript
import { verifyAccessTokenSafe, TokenErrorCode } from "serverless-crypto-utils";

const result = await verifyAccessTokenSafe({
  encryptionSecret: "your-32-char-encryption-secret",
  signingSecret: "your-hmac-signing-secret",
  accessToken: token,
});

if (result.success) {
  const payload = JSON.parse(result.data);
  console.log("Login successful:", payload.username);
} else {
  console.log(`Error ${result.error.code}: ${result.error.message}`);
}
```

| Parameter          | Type   | Description                                  |
| ------------------ | ------ | -------------------------------------------- |
| `encryptionSecret` | string | Secret used for encryption                   |
| `signingSecret`    | string | Secret used for signing                      |
| `accessToken`      | string | Token in format `iv.encryptedData.signature` |

**Error Codes:**

- `INVALID_FORMAT` - Malformed token
- `SIGNATURE_VERIFICATION_FAILED` - Invalid signature
- `TOKEN_EXPIRED` - Expired token
- `INVALID_JSON` - Payload is not valid JSON
- `DECRYPTION_FAILED` - Decryption error

## 🔒 Security

- Unique random initialization vector (IV) per token (12 bytes).
- AES-256-GCM encryption for confidentiality.
- HMAC-SHA256 signature for integrity and authenticity.
- Automatic expiration with integrated timestamp.
- Separate secrets for encryption and signing.

## 📌 Complete Example

```typescript
import {
  createAccessToken,
  verifyAccessTokenSafe,
  TokenErrorCode,
} from "serverless-crypto-utils";

const encryptionSecret = process.env.TOKEN_ENCRYPTION_SECRET;
const signingSecret = process.env.TOKEN_SIGNING_SECRET;

// Create token
const token = await createAccessToken({
  encryptionSecret,
  signingSecret,
  payload: { userId: 123, role: "admin" },
  expiresInSeconds: 900, // 15 minutes
});

console.log("Token:", token);

// Verify token
const result = await verifyAccessTokenSafe({
  encryptionSecret,
  signingSecret,
  accessToken: token,
});

if (result.success) {
  const user = JSON.parse(result.data);
  console.log("Access granted:", user.userId);
} else {
  console.log("Access denied:", result.error.message);
}
```

## 💡 Usage with Hono (Cloudflare Workers)

```typescript
import { Hono } from "hono";
import { verifyAccessTokenSafe, TokenErrorCode } from "serverless-crypto-utils";

type Bindings = {
  TOKEN_ENCRYPTION_SECRET: string;
  TOKEN_SIGNING_SECRET: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Authentication middleware
const authMiddleware = async (c, next) => {
  const token = c.req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return c.json({ error: "Token required" }, 401);
  }

  const result = await verifyAccessTokenSafe({
    encryptionSecret: c.env.TOKEN_ENCRYPTION_SECRET,
    signingSecret: c.env.TOKEN_SIGNING_SECRET,
    accessToken: token,
  });

  if (!result.success) {
    const status =
      result.error.code === TokenErrorCode.TOKEN_EXPIRED ? 401 : 403;
    return c.json({ error: result.error.message }, status);
  }

  c.set("user", JSON.parse(result.data));
  await next();
};

// Protected route
app.use("/api/protected/*", authMiddleware);
app.get("/api/protected/profile", (c) => {
  const user = c.get("user");
  return c.json({ message: "User profile", user });
});

export default app;
```
