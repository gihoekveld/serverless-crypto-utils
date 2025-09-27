# 🔒 Serverless Crypto Utilities

Serverless Crypto Utilities é um pacote minimalista para operações criptográficas rápidas e seguras na Edge.

[![npm](https://img.shields.io/npm/v/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
[![npm downloads](https://img.shields.io/npm/dt/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
![Build](https://github.com/gihoekveld/serverless-crypto-utils/actions/workflows/build.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Serverless Crypto Utilities é um pacote minimalista para operações criptográficas rápidas e seguras na Edge.

O pacote fornece funções para **hashing, criptografia, geração de tokens e outras operações criptográficas**, projetadas para máxima performance, baixo bundle size e segurança nativa.

Todas as funções utilizam exclusivamente a **Web Crypto API**, sem dependências externas.

## 🔹 Estrutura do pacote

O pacote é dividido em categorias de funções:

| Categoria                                           | Descrição                                                            | Exemplos de Funções              |
| :-------------------------------------------------- | :------------------------------------------------------------------- | :------------------------------- |
| password-hashing [README](docs/password-hashing.md) | Funções para gerar e verificar hashes de senhas (PBKDF2-HMAC-SHA256) | `hashPassword`, `verifyPassword` |
| id-generation [README](docs/id-generation.md)       | Funções para gerar IDs únicos                                        | `uuidV4`, `ulid`                 |
| criptografia [em breve]                             | Funções para criptografia simétrica e assimétrica                    | `encrypt`, `decrypt`             |

Atualmente o pacote inclui apenas os úteis de hash de senha. Novos módulos serão adicionados progressivamente.

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

## 🚀 Uso Básico

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

> Para detalhes completos, consulte [README](docs/password-hashing.md)

## 🔒 Segurança

- Todos os algoritmos usam a Web Crypto API nativa, garantindo segurança nativa e compatibilidade com Workers.
- Salt aleatório e pepper opcional para proteção adicional.
- Comparações timing-safe para evitar ataques de tempo.

📌 Roadmap

| #   | Funcionalidade                         | Status    |
| --- | -------------------------------------- | --------- |
| 1   | Hashing genérico (SHA-256, SHA-512)    | Planejado |
| 2   | Criptografia simétrica (AES-GCM)       | Planejado |
| 3   | Funções para geração de tokens seguros | Planejado |
| 4   | Helpers para JWT e HMAC                | Planejado |

🤝 Contribuição

Contribuições, sugestões e correções são bem-vindas! Abra issues ou PRs no GitHub para colaborar.
