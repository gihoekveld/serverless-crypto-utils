# 🔒 Serverless Crypto Utilities

[![npm](https://img.shields.io/npm/v/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
[![npm downloads](https://img.shields.io/npm/dt/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
![Build](https://github.com/gihoekveld/serverless-crypto-utils/actions/workflows/build.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Serverless Crypto Utilities é um pacote minimalista para operações criptográficas rápidas e seguras na Edge.

O pacote fornece funções para **hashing, criptografia, geração de tokens e outras operações criptográficas**, projetadas para máxima performance, baixo bundle size e segurança nativa.

Todas as funções utilizam exclusivamente a **Web Crypto API**, sem dependências externas.

## 🔹 Estrutura do Pacote

O pacote é dividido em categorias de funções:

| Categoria                                           | Descrição                                                                           | Exemplos de Funções                          |
| :-------------------------------------------------- | :---------------------------------------------------------------------------------- | :------------------------------------------- |
| password-hashing [README](docs/password-hashing.md) | Funções para gerar e verificar hashes de senhas (PBKDF2-HMAC-SHA256)                | `hashPassword`, `verifyPassword`             |
| access-token [README](docs/access-token.md)         | Funções para criar e verificar tokens de acesso seguros (AES-256-GCM + HMAC-SHA256) | `createAccessToken`, `verifyAccessTokenSafe` |
| id-generation [README](docs/id-generation.md)       | Funções para gerar IDs únicos                                                       | `uuidV4`, `ulid`                             |
| criptografia [em breve]                             | Funções para criptografia simétrica e assimétrica                                   | `encrypt`, `decrypt`                         |

Atualmente o pacote inclui módulos para hashing de senhas, tokens de acesso seguros e geração de IDs. Novos módulos serão adicionados progressivamente.

---

## ✅ Por Que Usar?

- **Velocidade na Edge:** Utiliza a API nativa do _runtime_, otimizada para o _serverless_.
- **Portabilidade:** Funciona em qualquer plataforma que suporte o _runtime_ Web Crypto (Cloudflare, Deno, etc.).
- **Segurança:** Implementa algoritmos padrão do setor para autenticação e _hashing_ de senhas.

## ⚡ Instalação

```bash
npm install serverless-crypto-utils
# ou
yarn add serverless-crypto-utils
# ou
pnpm add serverless-crypto-utils
```

### 📦 Bundle Size Optimization

### Importação Modular vs Completa

| Módulo             | Size (ESM) | Size (CJS) | Use Case                  |
| :----------------- | :--------- | :--------- | :------------------------ |
| `password-hashing` | 117 B      | 3.45 KB    | Apenas autenticação       |
| `access-token`     | 219 B      | 9.43 KB    | Apenas tokens seguros     |
| `id-generation`    | 85 B       | 1.64 KB    | Apenas geração de IDs     |
| **Full package**   | 399 B      | 12.53 KB   | Múltiplas funcionalidades |

### Exemplo de Otimização

```typescript
// ❌ Bundle maior (12.53 KB)
import { hashPassword } from "serverless-crypto-utils";

// ✅ Bundle menor (3.45 KB)
import { hashPassword } from "serverless-crypto-utils/password-hashing";
```

**Redução de até 73% no bundle size** usando imports modulares! 🚀

Para reduzir o bundle size, você pode importar apenas as funções que precisa:

```typescript
// Apenas password hashing
import {
  hashPassword,
  verifyPassword,
} from "serverless-crypto-utils/password-hashing";

// Apenas access tokens
import {
  createAccessToken,
  verifyAccessTokenSafe,
} from "serverless-crypto-utils/access-token";

// Apenas ID generation
import { uuidV4, ulid } from "serverless-crypto-utils/id-generation";
```

### 📦 Import Completo

Ou importe tudo de uma vez:

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

## 🚀 Uso Básico

### Password Hashing

```typescript
import {
  hashPassword,
  verifyPassword,
} from "serverless-crypto-utils/password-hashing";

const pepper = process.env.PEPPER || "secretGlobalPepper";

const hash = await hashPassword("superSenha123", { pepper });
const isValid = await verifyPassword("superSenha123", hash, { pepper });

console.log("Hash:", hash);
console.log("Senha correta?", isValid);
```

### Access Token

```typescript
import {
  createAccessToken,
  verifyAccessTokenSafe,
  TokenErrorCode,
} from "serverless-crypto-utils/access-token";

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
```

### ID Generation

```typescript
import { uuidV4, ulid } from "serverless-crypto-utils/id-generation";

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
