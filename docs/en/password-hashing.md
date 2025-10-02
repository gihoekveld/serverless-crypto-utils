# Password Hashing

_🇺🇸 English | [🇧🇷 Português](../pt-BR/password-hashing.md)_

Simple and secure password encryption using **PBKDF2** with **HMAC-SHA256**.

Designed for **Serverless/Edge** environments like Cloudflare Workers, with support for **salt**, **pepper**, and configurable **iterations**.

## 🔑 Main Functions

### `hashPassword(password, options?)`

Generates a secure hash for a password.

```typescript
import { hashPassword } from "serverless-crypto-utils";

const hashed = await hashPassword("mySecretPassword", {
  pepper: "myPepper", // optional, global secret
  iterations: 500_000, // optional, between 1000 and 1_000_000
  saltInBase64Url: "randomSaltInBase64Url", // optional, custom salt in base64url
});

console.log(hashed); // e.g. "500000.randomSaltInBase64Url.hashInBase64Url"
```

| Parameter                 | Type   | Description                                                             |
| ------------------------- | ------ | ----------------------------------------------------------------------- |
| `password`                | string | The password to be hashed                                               |
| `options.pepper`          | string | Optional secret value added to the password before hashing              |
| `options.iterations`      | number | Number of PBKDF2 iterations (1000–1_000_000). Default: 310_000          |
| `options.saltInBase64Url` | string | Optional salt in Base64URL. If not provided, will be generated randomly |

### `verifyPassword(password, stored, options?)`

Verifies if a password matches a stored hash.

```typescript
import { verifyPassword } from "serverless-crypto-utils";

const isValid = await verifyPassword(
  "mySecretPassword",
  "500000.randomSaltInBase64Url.hashInBase64Url",
  { pepper: "myPepper" } // optional
);

console.log(isValid); // true or false
```

| Parameter        | Type   | Description                                      |
| ---------------- | ------ | ------------------------------------------------ |
| `password`       | string | The password to be verified                      |
| `stored`         | string | The stored hash in format `iterations.salt.hash` |
| `options.pepper` | string | Pepper used in hash creation (if any)            |

## 🔒 Security

- Unique random salt per password (16 bytes).
- Optional pepper (global secret) to protect against database leaks.
- Configurable iterations to balance security and performance.
- Timing-safe comparison, resistant to timing attacks.

📌 Complete Example

```typescript
import { hashPassword, verifyPassword } from "serverless-crypto-utils";

const pepper = process.env.PEPPER || "secretGlobalPepper";

// Generate hash
const hash = await hashPassword("superPassword123", { pepper });
console.log("Hash:", hash);

// Verify password
const valid = await verifyPassword("superPassword123", hash, { pepper });
console.log("Password valid?", valid);
```
