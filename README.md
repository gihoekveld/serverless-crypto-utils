# 🔒 Serverless Crypto Utilities

[![npm](https://img.shields.io/npm/v/serverless-crypto-utils)](https://www.npmjs.co```

## 🏗️ Framework Examples

### Hono (Cloudflare Workers)

```typescript
import { Hono } from "hono";
import { hashPassword, verifyPassword } from "serverless-crypto-utils";

const app = new Hono();

app.post("/register", async (c) => {
  const { email, password } = await c.req.json();

  const hashedPassword = await hashPassword(password);

  // Save user to database
  await saveUser({ email, hashedPassword });

  return c.json({ success: true });
});

app.post("/login", async (c) => {
  const { email, password } = await c.req.json();

  const user = await getUser(email);
  const isValidPassword = await verifyPassword(password, user.hashedPassword);

  if (isValidPassword) {
    return c.json({ success: true, token: "jwt-token" });
  }

  return c.json({ error: "Invalid credentials" }, 401);
});

export default app;
```

### Next.js API Routes

```typescript
// pages/api/auth/register.ts
import { hashPassword } from "serverless-crypto-utils";
import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { password } = req.body;

  try {
    const hashedPassword = await hashPassword(password);
    // Save to database...

    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
}
```

## 📦 Bundle Size

- **Package size**: 8.5 kB (gzipped)
- **Unpacked size**: 45.4 kB
- **Zero dependencies**: No external libraries
- **Tree-shakeable**: Import only what you need

## 🧪 Testing

The package includes comprehensive tests with 86%+ code coverage:

```bash
npm test           # Run all tests
npm run test:watch # Watch mode
npm run test:coverage # Generate coverage report
```

## 🔐 Security

- **Web Crypto API**: Uses browser/runtime native cryptographic functions
- **Industry Standards**: PBKDF2-HMAC-SHA256, AES-256-GCM, HMAC-SHA256
- **No Dependencies**: Reduces attack surface
- **Constant Time**: Operations designed to prevent timing attacks

## 📋 Requirements

- Node.js 18+ or any runtime with Web Crypto API support
- TypeScript 4.5+ (for TypeScript projects)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

MIT © [Giselle Hoekveld Silva](https://github.com/gihoekveld)

## 🔗 Links

- [npm package](https://www.npmjs.com/package/serverless-crypto-utils)
- [GitHub repository](https://github.com/gihoekveld/serverless-crypto-utils)
- [Documentation](docs/)
- [Issues](https://github.com/gihoekveld/serverless-crypto-utils/issues)erverless-crypto-utils)
  [![npm downloads](https://img.shields.io/npm/dt/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
  ![Build](https://github.com/gihoekveld/serverless-crypto-utils/actions/workflows/build.yml/badge.svg)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 📖 **[Leia em Português](README.pt-BR.md)** | **[Read in English](README.md)**

A minimalist crypto toolkit for fast and secure cryptographic operations on the Edge.

This package provides functions for **password hashing, encryption, secure token generation, and other cryptographic operations**, designed for maximum performance, minimal bundle size, and native security.

All functions use exclusively the **Web Crypto API** with zero external dependencies.

## 🔹 Package Structure

The package is organized into function categories:

| Category                                            | Description                                                                     | Example Functions                            |
| :-------------------------------------------------- | :------------------------------------------------------------------------------ | :------------------------------------------- |
| password-hashing [README](docs/password-hashing.md) | Functions to generate and verify password hashes (PBKDF2-HMAC-SHA256)           | `hashPassword`, `verifyPassword`             |
| access-token [README](docs/access-token.md)         | Functions to create and verify secure access tokens (AES-256-GCM + HMAC-SHA256) | `createAccessToken`, `verifyAccessTokenSafe` |
| id-generation [README](docs/id-generation.md)       | Functions to generate unique IDs                                                | `uuidV4`, `ulid`                             |
| encryption [coming soon]                            | Functions for symmetric and asymmetric encryption                               | `encrypt`, `decrypt`                         |

Currently the package includes modules for password hashing, secure access tokens, and ID generation. New modules will be added progressively.

---

## ✅ Why Use This Package?

- **Edge Performance:** Uses native runtime APIs, optimized for serverless environments.
- **Portability:** Works on any platform supporting Web Crypto runtime (Cloudflare, Deno, etc.).
- **Security:** Implements industry-standard algorithms for authentication and password hashing.
- **Zero Dependencies:** No external dependencies, reducing bundle size and security surface.
- **TypeScript Native:** Full TypeScript support with comprehensive type definitions.

## ⚡ Installation

```bash
npm install serverless-crypto-utils
# or
yarn add serverless-crypto-utils
# or
pnpm add serverless-crypto-utils
```

## 🚀 Basic Usage

### Password Hashing

```typescript
import { hashPassword, verifyPassword } from "serverless-crypto-utils";

// Hash a password
const hashedPassword = await hashPassword("mySecretPassword");
console.log(hashedPassword);
// Output: "500000.RANDOM_SALT_BASE64.HASHED_PASSWORD_BASE64"

// Verify a password
const isValid = await verifyPassword("mySecretPassword", hashedPassword);
console.log(isValid); // true
```

### Access Tokens

```typescript
import {
  createAccessToken,
  verifyAccessTokenSafe,
  TokenErrorCode,
} from "serverless-crypto-utils";

// Create a secure access token
const token = await createAccessToken({
  encryptionSecret: "your-encryption-secret-32-chars-min",
  signingSecret: "your-signing-secret-for-hmac-256",
  payload: {
    userId: 12345,
    username: "john_doe",
    role: "admin",
  },
  expiresInSeconds: 3600, // 1 hour
});

// Verify token safely (returns Result pattern)
const result = await verifyAccessTokenSafe({
  encryptionSecret: "your-encryption-secret-32-chars-min",
  signingSecret: "your-signing-secret-for-hmac-256",
  accessToken: token,
});

if (result.success) {
  const payload = JSON.parse(result.data);
  console.log("User:", payload.username);
} else {
  console.error("Token error:", result.error.code);
}
```

### ID Generation

```typescript
import { uuidV4, ulid } from "serverless-crypto-utils";

// Generate UUID v4
const uuid = uuidV4();
console.log(uuid); // "f47ac10b-58cc-4372-a567-0e02b2c3d479"

// Generate ULID (sortable)
const id = ulid();
console.log(id); // "01ARZ3NDEKTSV4RRFFQ69G5FAV"
```

hashPassword,
verifyPassword,
} from "serverless-crypto-utils/password-hashing";

const pepper = process.env.PEPPER || "secretGlobalPepper";

const hash = await hashPassword("superSenha123", { pepper });
const isValid = await verifyPassword("superSenha123", hash, { pepper });

console.log("Hash:", hash);
console.log("Senha correta?", isValid);

````

### Access Token

```typescript
import {
  createAccessToken,
  verifyAccessTokenSafe,
  TokenErrorCode,
} from "serverless-crypto-utils";

// Criar token
const token = await createAccessToken({
  encryptionSecret: process.env.TOKEN_ENCRYPTION_SECRET,
  signingSecret: process.env.TOKEN_SIGNING_SECRET,
  payload: { userId: 123, role: "admin" },
  expiresInSeconds: 900, // 15 minutos
});

// Verificar token
const result = await verifyAccessTokenSafe({
  encryptionSecret: process.env.TOKEN_ENCRYPTION_SECRET,
  signingSecret: process.env.TOKEN_SIGNING_SECRET,
  accessToken: token,
});

if (result.success) {
  const user = JSON.parse(result.data);
  console.log("Acesso autorizado:", user.userId);
} else {
  console.log("Acesso negado:", result.error.message);
}
````

### ID Generation

```typescript
import { uuidV4, ulid } from "serverless-crypto-utils";

// Gerar UUID v4
const uuid = uuidV4();
console.log("UUID:", uuid); // e.g. "3b12f1df-5232-4f0c-8b1d-3f3f9f1b5ec1"

// Gerar ULID (lexicograficamente ordenável)
const ulidId = ulid();
console.log("ULID:", ulidId); // e.g. "01F8MECHZX3TBDSZ7EXAMPLE"
```

> Para detalhes completos, consulte:
>
> - [Password Hashing](docs/password-hashing.md)
> - [Access Token](docs/access-token.md)
> - [ID Generation](docs/id-generation.md)

## 🔒 Segurança

- Todos os algoritmos usam a Web Crypto API nativa, garantindo segurança nativa e compatibilidade com Workers.
- **Password Hashing**: Salt aleatório e pepper opcional para proteção adicional.
- **Access Tokens**: Criptografia AES-256-GCM + assinatura HMAC-SHA256 com expiração automática.
- **Comparações timing-safe** para evitar ataques de tempo.
- **Zero dependências externas** para minimizar superfície de ataque.

## 📌 Roadmap

| #   | Funcionalidade                            | Status    |
| --- | ----------------------------------------- | --------- |
| ✅  | Password hashing (PBKDF2-HMAC-SHA256)     | Concluído |
| ✅  | Access tokens (AES-256-GCM + HMAC-SHA256) | Concluído |
| ✅  | Geração de IDs únicos (UUID, ULID)        | Concluído |
| 🔄  | Hashing genérico (SHA-256, SHA-512)       | Planejado |
| 🔄  | Criptografia simétrica (AES-GCM)          | Planejado |
| 🔄  | Helpers para JWT                          | Planejado |

## 🤝 Contribuição

Contribuições, sugestões e correções são bem-vindas! Abra issues ou PRs no GitHub para colaborar.
