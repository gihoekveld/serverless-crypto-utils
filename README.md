# 🔒 Serverless Crypto Utilities

_🇺🇸 English | [🇧🇷 Português](README.pt-BR.md)_

[![npm](https://img.shields.io/npm/v/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
[![npm downloads](https://img.shields.io/npm/dt/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
![Build](https://github.com/gihoekveld/serverless-crypto-utils/actions/workflows/build.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A minimalist toolkit for fast and secure cryptographic operations on the Edge.

This package provides functions for **hashing, encryption, token generation, and other cryptographic operations**, designed for maximum performance, low bundle size, and native security.

All functions use exclusively the **Web Crypto API** with zero external dependencies.

## 🔹 Package Structure

The package is organized into functional categories:

| Category                                               | Description                                                                           | Example Functions                            |
| :----------------------------------------------------- | :------------------------------------------------------------------------------------ | :------------------------------------------- |
| password-hashing [README](docs/en/password-hashing.md) | Functions for generating and verifying password hashes (PBKDF2-HMAC-SHA256)           | `hashPassword`, `verifyPassword`             |
| access-token [README](docs/en/access-token.md)         | Functions for creating and verifying secure access tokens (AES-256-GCM + HMAC-SHA256) | `createAccessToken`, `verifyAccessTokenSafe` |
| id-generation [README](docs/en/id-generation.md)       | Functions for generating unique IDs                                                   | `uuidV4`, `ulid`                             |
| encryption [coming soon]                               | Functions for symmetric and asymmetric encryption                                     | `encrypt`, `decrypt`                         |

Currently, the package includes modules for password hashing, secure access tokens, and ID generation. New modules will be added progressively.

---

## ✅ Why Use This?

- **Edge Speed:** Uses native runtime APIs optimized for serverless environments.
- **Portability:** Works on any platform supporting Web Crypto runtime (Cloudflare Workers, Deno, etc.).
- **Security:** Implements industry-standard algorithms for authentication and password hashing.

## ⚡ Installation

```bash
npm install serverless-crypto-utils
# or
yarn add serverless-crypto-utils
# or
pnpm add serverless-crypto-utils
```

## 📦 Bundle Size Optimization

### Modular vs Full Import

| Module             | Size (ESM) | Size (CJS) | Use Case                 |
| :----------------- | :--------- | :--------- | :----------------------- |
| `password-hashing` | 117 B      | 3.45 KB    | Authentication only      |
| `access-token`     | 219 B      | 9.43 KB    | Secure tokens only       |
| `id-generation`    | 85 B       | 1.64 KB    | ID generation only       |
| **Full package**   | 399 B      | 12.53 KB   | Multiple functionalities |

### Optimization Example

```typescript
// ❌ Larger bundle (12.53 KB)
import { hashPassword } from "serverless-crypto-utils";

// ✅ Smaller bundle (3.45 KB)
import { hashPassword } from "serverless-crypto-utils/password-hashing";
```

**Up to 73% bundle size reduction** using modular imports! 🚀

To reduce bundle size, you can import only the functions you need:

```typescript
// Password hashing only
import {
  hashPassword,
  verifyPassword,
} from "serverless-crypto-utils/password-hashing";

// Access tokens only
import {
  createAccessToken,
  verifyAccessTokenSafe,
} from "serverless-crypto-utils/access-token";

// ID generation only
import { uuidV4, ulid } from "serverless-crypto-utils/id-generation";
```

### 📦 Full Import

Or import everything at once:

```typescript
import {
  hashPassword,
  verifyPassword,
  createAccessToken,
  verifyAccessTokenSafe,
  uuidV4,
  ulid,
} from "serverless-crypto-utils";
```

## 🚀 Basic Usage

### Password Hashing

```typescript
import {
  hashPassword,
  verifyPassword,
} from "serverless-crypto-utils/password-hashing";

const pepper = process.env.PEPPER || "secretGlobalPepper";

const hash = await hashPassword("superPassword123", { pepper });
const isValid = await verifyPassword("superPassword123", hash, { pepper });

console.log("Hash:", hash);
console.log("Password valid?", isValid);
```

### Access Token

```typescript
import {
  createAccessToken,
  verifyAccessTokenSafe,
  TokenErrorCode,
} from "serverless-crypto-utils/access-token";

// Create token
const token = await createAccessToken({
  encryptionSecret: process.env.TOKEN_ENCRYPTION_SECRET,
  signingSecret: process.env.TOKEN_SIGNING_SECRET,
  payload: { userId: 123, role: "admin" },
  expiresInSeconds: 900, // 15 minutes
});

// Verify token
const result = await verifyAccessTokenSafe({
  encryptionSecret: process.env.TOKEN_ENCRYPTION_SECRET,
  signingSecret: process.env.TOKEN_SIGNING_SECRET,
  accessToken: token,
});

if (result.success) {
  const user = JSON.parse(result.data);
  console.log("Access granted:", user.userId);
} else {
  console.log("Access denied:", result.error.message);
}
```

### ID Generation

```typescript
import { uuidV4, ulid } from "serverless-crypto-utils/id-generation";

// Generate UUID v4
const uuid = uuidV4();
console.log("UUID:", uuid); // e.g. "3b12f1df-5232-4f0c-8b1d-3f3f9f1b5ec1"

// Generate ULID (lexicographically sortable)
const ulidId = ulid();
console.log("ULID:", ulidId); // e.g. "01F8MECHZX3TBDSZ7EXAMPLE"
```

> For complete details, see:
>
> - [Password Hashing](docs/en/password-hashing.md)
> - [Access Token](docs/en/access-token.md)
> - [ID Generation](docs/en/id-generation.md)

## 🔒 Security

All algorithms use the native Web Crypto API, ensuring native security and Worker compatibility.

- **Password Hashing**: Random salt and optional pepper for additional protection.
- **Access Tokens**: AES-256-GCM encryption + HMAC-SHA256 signature with automatic expiration.
- **Timing-safe comparisons** to prevent timing attacks.
- **Zero external dependencies** to minimize attack surface.

## 📌 Roadmap

| #   | Feature                                   | Status   |
| --- | ----------------------------------------- | -------- |
| ✅  | Password hashing (PBKDF2-HMAC-SHA256)     | Complete |
| ✅  | Access tokens (AES-256-GCM + HMAC-SHA256) | Complete |
| ✅  | Unique ID generation (UUID, ULID)         | Complete |
| 🔄  | Generic hashing (SHA-256, SHA-512)        | Planned  |
| 🔄  | Symmetric encryption (AES-GCM)            | Planned  |
| 🔄  | JWT helpers                               | Planned  |

## 🤝 Contributing

Contributions, suggestions, and bug reports are welcome! Open issues or PRs on GitHub to collaborate.
