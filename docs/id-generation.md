# ID Generation

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
