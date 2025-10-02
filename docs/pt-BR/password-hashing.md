# Password Hashing

_[🇺🇸 English](../en/password-hashing.md) | 🇧🇷 Português_

Criptografia de senhas simples e segura usando **PBKDF2** com **HMAC-SHA256**.

Projetado para ambientes **Serverless/Edge**, como Cloudflare Workers, com suporte a **salt**, **pepper** e número configurável de **iterações**.

## 🔑 Funções Principais

### `hashPassword(password, options?)`

Gera um hash seguro para uma senha.

```typescript
import { hashPassword } from "serverless-crypto-utils";

const hashed = await hashPassword("mySecretPassword", {
  pepper: "myPepper", // opcional, segredo global
  iterations: 500_000, // opcional, entre 1000 e 1_000_000
  saltInBase64Url: "randomSaltInBase64Url", // opcional, salt personalizado em base64url
});

console.log(hashed); // e.g. "500000.randomSaltInBase64Url.hashInBase64Url"
```

| Parâmetro                 | Tipo   | Descrição                                                                |
| ------------------------- | ------ | ------------------------------------------------------------------------ |
| `password`                | string | A senha a ser hasheada                                                   |
| `options.pepper`          | string | Valor secreto opcional adicionado à senha antes do hash.                 |
| `options.iterations`      | number | Número de iterações PBKDF2 (1000–1_000_000). Default: 310_000            |
| `options.saltInBase64Url` | string | Salt opcional em Base64URL. Se não informado, será gerado aleatoriamente |

### `verifyPassword(password, stored, options?)`

Verifica se uma senha corresponde a um hash armazenado.

```typescript
import { verifyPassword } from "serverless-crypto-utils";

const isValid = await verifyPassword(
  "mySecretPassword",
  "500000.randomSaltInBase64Url.hashInBase64Url",
  { pepper: "myPepper" } // opcional
);

console.log(isValid); // true ou false
```

| Parâmetro        | Tipo   | Descrição                                           |
| ---------------- | ------ | --------------------------------------------------- |
| `password`       | string | A senha a ser verificada                            |
| `stored`         | string | O hash armazenado no formato `iterations.salt.hash` |
| `options.pepper` | string | Pepper usado na criação do hash (se houver)         |

## 🔒 Segurança

- Salt aleatório único por senha (16 bytes).
- Pepper opcional (secreto global) para proteger contra vazamento do banco.
- Iterações configuráveis para balancear segurança e performance.
- Comparação timing-safe, resistente a ataques de tempo.

📌 Exemplo completo

```typescript
import { hashPassword, verifyPassword } from "serverless-crypto-utils";

const pepper = process.env.PEPPER || "secretGlobalPepper";

// Gerar hash
const hash = await hashPassword("superSenha123", { pepper });
console.log("Hash:", hash);

// Verificar senha
const valid = await verifyPassword("superSenha123", hash, { pepper });
console.log("Senha correta?", valid);
```
