# 🔒 Serverless Crypto Utilities

[![npm](https://img.shields.io/npm/v/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
[![npm downloads](https://img.shields.io/npm/dm/serverless-crypto-utils)](https://www.npmjs.com/package/serverless-crypto-utils)
![Build](https://github.com/gihoekveld/serverless-crypto-utils/actions/workflows/build.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Este é um pacote de utilitários criptográficos para ambientes _Serverless_ e **Edge Computing**, como **Cloudflare Workers** ou Vercel Edge Functions.

Fornece funções seguras para hashing, criptografia, geração de tokens e outras operações criptográficas, projetadas para alta performance e facilidade de uso.

A biblioteca utiliza exclusivamente a **Web Crypto API** nativa, garantindo velocidade máxima e um _bundle size_ mínimo, sem dependências externas.

## 🔹 Estrutura do pacote

O pacote é dividido em categorias de funções:

| Categoria                                           | Descrição                                                            | Exemplos de Funções              |
| :-------------------------------------------------- | :------------------------------------------------------------------- | :------------------------------- |
| password-hashing [README](docs/password-hashing.md) | Funções para gerar e verificar hashes de senhas (PBKDF2-HMAC-SHA256) | `hashPassword`, `verifyPassword` |

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

- Adicionar hashing genérico (SHA-256, SHA-512).
- Criptografia simétrica (AES-GCM).
- Funções para geração de tokens seguros (UUID, random bytes).
- Helpers para JWT e HMAC.
