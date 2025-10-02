# Encryption

_[🇺🇸 English](../en/encryption.md) | 🇧🇷 Português_

Criptografia simples e segura de dados usando o algoritmo **AES-256-GCM**.

Projetado para ambientes **Serverless/Edge** como Cloudflare Workers, com suporte para criptografia de **strings** e **objetos** usando apenas a Web Crypto API.

## 🔑 Funções Principais

### Criptografia de Strings

#### `encrypt(data, secret)`

Criptografa uma string usando o algoritmo AES-256-GCM.

```typescript
import { encrypt } from "serverless-crypto-utils/encryption";

const encrypted = await encrypt("dados sensíveis", "minhaChaveSecreta");
console.log(encrypted); // "ivBase64.encryptedDataBase64"
```

| Parâmetro | Tipo   | Descrição                                                                       |
| --------- | ------ | ------------------------------------------------------------------------------- |
| `data`    | string | A string de texto plano para criptografar                                       |
| `secret`  | string | A chave secreta para criptografia (qualquer tamanho, normalizada para 32 bytes) |

#### `decrypt(encryptedData, secret)`

Descriptografa uma string que foi criptografada com a função encrypt.

```typescript
import { decrypt } from "serverless-crypto-utils/encryption";

const decrypted = await decrypt(
  "ivBase64.encryptedDataBase64",
  "minhaChaveSecreta"
);
console.log(decrypted); // "dados sensíveis"
```

| Parâmetro       | Tipo   | Descrição                                                      |
| --------------- | ------ | -------------------------------------------------------------- |
| `encryptedData` | string | Os dados criptografados no formato "iv.encryptedData" (Base64) |
| `secret`        | string | A chave secreta usada para criptografia                        |

### Criptografia de Objetos

#### `encryptObject<T>(object, secret)`

Criptografa um objeto convertendo-o para JSON e depois criptografando a string.

```typescript
import { encryptObject } from "serverless-crypto-utils/encryption";

const usuario = { nome: "João", email: "joao@exemplo.com", idade: 30 };
const encrypted = await encryptObject(usuario, "minhaChaveSecreta");
console.log(encrypted); // "ivBase64.encryptedDataBase64"
```

| Parâmetro | Tipo   | Descrição                         |
| --------- | ------ | --------------------------------- |
| `object`  | T      | O objeto para criptografar        |
| `secret`  | string | A chave secreta para criptografia |

#### `decryptObject<T>(encryptedData, secret)`

Descriptografa um objeto que foi criptografado com encryptObject.

```typescript
import { decryptObject } from "serverless-crypto-utils/encryption";

type Usuario = { nome: string; email: string; idade: number };
const decrypted = await decryptObject<Usuario>(
  "ivBase64.encryptedDataBase64",
  "minhaChaveSecreta"
);
console.log(decrypted); // { nome: "João", email: "joao@exemplo.com", idade: 30 }
```

| Parâmetro       | Tipo   | Descrição                                                      |
| --------------- | ------ | -------------------------------------------------------------- |
| `encryptedData` | string | Os dados criptografados no formato "iv.encryptedData" (Base64) |
| `secret`        | string | A chave secreta usada para criptografia                        |

## 🛡️ Versões Seguras (Result Pattern)

Todas as funções têm versões "Safe" que usam o Result Pattern em vez de lançar exceções:

```typescript
import {
  encryptSafe,
  decryptSafe,
  encryptObjectSafe,
  decryptObjectSafe,
  EncryptionErrorCode,
} from "serverless-crypto-utils/encryption";

const result = await encryptSafe("dados sensíveis", "minhaChaveSecreta");
if (result.success) {
  console.log("Criptografado:", result.data);
} else {
  console.error(`Erro ${result.error.code}: ${result.error.message}`);
}
```

**Códigos de Erro:**

- `INVALID_FORMAT` - Dados criptografados malformados
- `ENCRYPTION_FAILED` - Operação de criptografia falhou
- `DECRYPTION_FAILED` - Operação de descriptografia falhou
- `INVALID_JSON` - Descriptografia de objeto falhou (JSON inválido)
- `INVALID_SECRET` - Chave inválida ou vazia fornecida

## 🔒 Recursos de Segurança

- **Criptografia AES-256-GCM** para confidencialidade e integridade
- **IV aleatório único** por criptografia (12 bytes)
- **Tratamento flexível de chaves** (qualquer tamanho, normalizado para 32 bytes)
- **Web Crypto API** para operações criptograficamente seguras
- **Sem dependências externas** para superfície mínima de ataque

## 📌 Exemplos Completos

### Criptografia Básica de String

```typescript
import { encrypt, decrypt } from "serverless-crypto-utils/encryption";

const secret = process.env.ENCRYPTION_SECRET || "minhaChaveSecreta";

// Criptografar dados sensíveis
const dadosSensiveis = "Cartão de crédito do usuário: 4532 1234 5678 9012";
const encrypted = await encrypt(dadosSensiveis, secret);

// Armazenar dados criptografados no banco
await database.store({ id: "user-123", encryptedData: encrypted });

// Mais tarde, recuperar e descriptografar
const record = await database.get("user-123");
const decrypted = await decrypt(record.encryptedData, secret);
console.log(decrypted); // "Cartão de crédito do usuário: 4532 1234 5678 9012"
```

### Criptografia de Objeto com TypeScript

```typescript
import {
  encryptObject,
  decryptObject,
} from "serverless-crypto-utils/encryption";

interface PerfilUsuario {
  id: number;
  nome: string;
  email: string;
  preferencias: {
    tema: string;
    notificacoes: boolean;
  };
}

const secret = process.env.ENCRYPTION_SECRET;

// Criptografar perfil do usuário
const perfil: PerfilUsuario = {
  id: 123,
  nome: "João Silva",
  email: "joao@exemplo.com",
  preferencias: {
    tema: "escuro",
    notificacoes: true,
  },
};

const perfilCriptografado = await encryptObject(perfil, secret);

// Armazenar no banco
await database.updateUser(123, { encryptedProfile: perfilCriptografado });

// Mais tarde, recuperar e descriptografar
const usuario = await database.getUser(123);
const perfilDescriptografado = await decryptObject<PerfilUsuario>(
  usuario.encryptedProfile,
  secret
);
console.log(perfilDescriptografado.nome); // "João Silva"
```

### Operações Seguras com Tratamento de Erro

```typescript
import {
  encryptObjectSafe,
  decryptObjectSafe,
  EncryptionErrorCode,
} from "serverless-crypto-utils/encryption";

async function armazenarDadosUsuarioSeguro(userId: string, dadosUsuario: any) {
  const secret = process.env.ENCRYPTION_SECRET;

  const result = await encryptObjectSafe(dadosUsuario, secret);

  if (!result.success) {
    console.error(`Criptografia falhou: ${result.error.message}`);
    throw new Error("Falha ao proteger dados do usuário");
  }

  await database.store({ userId, encryptedData: result.data });
  return true;
}

async function recuperarDadosUsuario(userId: string) {
  const secret = process.env.ENCRYPTION_SECRET;
  const record = await database.get(userId);

  const result = await decryptObjectSafe(record.encryptedData, secret);

  if (!result.success) {
    if (result.error.code === EncryptionErrorCode.DECRYPTION_FAILED) {
      console.error("Chave de criptografia inválida ou dados corrompidos");
    }
    return null;
  }

  return result.data;
}
```

## 🔍 Casos de Uso

### Quando usar:

- **Informações Pessoais Identificáveis (PII)** criptografia
- **Preferências sensíveis do usuário** armazenamento
- **Chaves de API e tokens** armazenamento
- **Informações de cartão de crédito ou pagamento** criptografia
- **Documentos médicos ou legais** criptografia
- **Cache de dados sensíveis temporários**

### Quando NÃO usar:

- **Senhas** (use o módulo `password-hashing` em vez disso)
- **Arquivos grandes** (considere criptografia em streaming)
- **Comunicação em tempo real** (overhead de alta latência)
- **Dados públicos** que não precisam de proteção
