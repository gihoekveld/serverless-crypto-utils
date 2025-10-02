# ID Generation

_[🇺🇸 English](../en/id-generation.md) | 🇧🇷 Português_

Funções para **geração de identificadores únicos** em ambientes **Serverless** e **Edge**, usando apenas APIs nativas do JavaScript.

## 🔑 Funções Principais

### `uuidV4()`

Gera um UUID v4 (Universally Unique Identifier) conforme o padrão RFC 4122.

```typescript
import { uuidV4 } from "serverless-crypto-utils";
const id = uuidV4();
console.log(id); // e.g. "3b12f1df-5232-4f0c-8b1d-3f3f9f1b5ec1"
```

### `ulid()`

Gera um ULID (Universally Unique Lexicographically Sortable Identifier).

```typescript
import { ulid } from "serverless-crypto-utils";
const id = ulid();
console.log(id); // e.g. "01F8MECHZX3TBDSZ7EXAMPLE"
```

## 🔍 Comparação

| Característica     | UUID v4                                | ULID                          |
| :----------------- | :------------------------------------- | :---------------------------- |
| **Formato**        | `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` | `01AN4Z07BY79KA1307SR9X4MV3`  |
| **Tamanho**        | 36 caracteres (com hífens)             | 26 caracteres                 |
| **Ordenável**      | ❌ Não                                 | ✅ Sim (lexicograficamente)   |
| **Timestamp**      | ❌ Não                                 | ✅ Sim (primeiros 48 bits)    |
| **Case-sensitive** | ❌ Não (maiúscula/minúscula)           | ✅ Não (só maiúsculas)        |
| **URL-safe**       | ⚠️ Hífens podem precisar de encoding   | ✅ Sim                        |
| **Índice de BD**   | ⚠️ Aleatório (performance ruim)        | ✅ Ordenado (boa performance) |

## 📌 Exemplos de Uso

### IDs de Usuário

```typescript
import { uuidV4 } from "serverless-crypto-utils";

const userId = uuidV4();
console.log(`Usuário criado com ID: ${userId}`);
```

### Chaves Primárias de Banco (Recomendado: ULID)

```typescript
import { ulid } from "serverless-crypto-utils";

// Melhor para performance do banco devido à ordenação lexicográfica
const orderId = ulid();
console.log(`Pedido criado com ID: ${orderId}`);
```

### IDs de Requisição de API

```typescript
import { ulid } from "serverless-crypto-utils";

const requestId = ulid();
console.log(`Request ID: ${requestId}`);
// Pode ser usado para rastreamento e debugging
```

## 🚀 Performance

- **Geração rápida**: Usa `crypto.getRandomValues()` nativo
- **Zero dependências**: Não requer bibliotecas externas
- **Otimizado para Edge**: Funciona no Cloudflare Workers, Deno e outros runtimes de edge
- **Eficiente em memória**: Alocação mínima de memória

## 🔒 Segurança

- **Criptograficamente seguro**: Usa Web Crypto API para aleatoriedade
- **Resistente a colisões**: Probabilidade extremamente baixa de duplicatas
- **Sem padrões previsíveis**: Não é possível adivinhar o próximo ID a partir dos anteriores

## 💡 Melhores Práticas

### Quando usar UUID v4:

- ✅ Identificadores de usuário
- ✅ IDs de sessão
- ✅ Tokens únicos
- ✅ Quando ordenação cronológica não é importante

### Quando usar ULID:

- ✅ Chaves primárias de banco de dados
- ✅ Entradas de log
- ✅ IDs de eventos
- ✅ Quando você precisa de identificadores ordenáveis
- ✅ Endpoints de API que se beneficiam de ordenação cronológica
