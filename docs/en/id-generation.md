# ID Generation

_🇺🇸 English | [🇧🇷 Português](../pt-BR/id-generation.md)_

Functions for **unique identifier generation** in **Serverless** and **Edge** environments, using only native JavaScript APIs.

## 🔑 Main Functions

### `uuidV4()`

Generates a UUID v4 (Universally Unique Identifier) according to RFC 4122 standard.

```typescript
import { uuidV4 } from "serverless-crypto-utils";
const id = uuidV4();
console.log(id); // e.g. "3b12f1df-5232-4f0c-8b1d-3f3f9f1b5ec1"
```

### `ulid()`

Generates a ULID (Universally Unique Lexicographically Sortable Identifier).

```typescript
import { ulid } from "serverless-crypto-utils";
const id = ulid();
console.log(id); // e.g. "01F8MECHZX3TBDSZ7EXAMPLE"
```

## 🔍 Comparison

| Feature            | UUID v4                                | ULID                          |
| :----------------- | :------------------------------------- | :---------------------------- |
| **Format**         | `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` | `01AN4Z07BY79KA1307SR9X4MV3`  |
| **Length**         | 36 characters (with hyphens)           | 26 characters                 |
| **Sortable**       | ❌ No                                  | ✅ Yes (lexicographically)    |
| **Timestamp**      | ❌ No                                  | ✅ Yes (first 48 bits)        |
| **Case-sensitive** | ❌ No (mixed case)                     | ✅ No (uppercase only)        |
| **URL-safe**       | ⚠️ Hyphens may need encoding           | ✅ Yes                        |
| **Database index** | ⚠️ Random (poor performance)           | ✅ Ordered (good performance) |

## 📌 Usage Examples

### User IDs

```typescript
import { uuidV4 } from "serverless-crypto-utils";

const userId = uuidV4();
console.log(`User created with ID: ${userId}`);
```

### Database Primary Keys (Recommended: ULID)

```typescript
import { ulid } from "serverless-crypto-utils";

// Better for database performance due to lexicographic ordering
const orderId = ulid();
console.log(`Order created with ID: ${orderId}`);
```

### API Request IDs

```typescript
import { ulid } from "serverless-crypto-utils";

const requestId = ulid();
console.log(`Request ID: ${requestId}`);
// Can be used for tracing and debugging
```

## 🚀 Performance

- **Fast generation**: Uses native `crypto.getRandomValues()`
- **Zero dependencies**: No external libraries required
- **Edge-optimized**: Works in Cloudflare Workers, Deno, and other edge runtimes
- **Memory efficient**: Minimal memory allocation

## 🔒 Security

- **Cryptographically secure**: Uses Web Crypto API for randomness
- **Collision-resistant**: Extremely low probability of duplicates
- **No predictable patterns**: Cannot guess next ID from previous ones

## 💡 Best Practices

### When to use UUID v4:

- ✅ User identifiers
- ✅ Session IDs
- ✅ One-time tokens
- ✅ When chronological ordering is not important

### When to use ULID:

- ✅ Database primary keys
- ✅ Log entries
- ✅ Event IDs
- ✅ When you need sortable identifiers
- ✅ API endpoints that benefit from chronological ordering
