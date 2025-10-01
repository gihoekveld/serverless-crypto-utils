# Access Token

Criação e verificação de tokens de acesso seguros usando **AES-256-GCM** para criptografia e **HMAC-SHA256** para assinatura.

Projetado para ambientes **Serverless/Edge**, como Cloudflare Workers, com suporte a **criptografia**, **assinatura** e **expiração automática**.

## 🔑 Funções Principais

### `createAccessToken(options)`

Cria um token de acesso seguro com payload criptografado.

```typescript
import { createAccessToken } from "serverless-crypto-utils";

const token = await createAccessToken({
  encryptionSecret: "seu-segredo-de-criptografia-32-chars",
  signingSecret: "seu-segredo-de-assinatura-hmac",
  payload: {
    userId: 12345,
    username: "usuario",
    role: "admin",
  },
  expiresInSeconds: 3600, // opcional, padrão: 3600 (1 hora)
});

console.log(token); // e.g. "ivBase64.encryptedDataBase64.signatureBase64"
```

| Parâmetro          | Tipo                | Descrição                                              |
| ------------------ | ------------------- | ------------------------------------------------------ |
| `encryptionSecret` | string              | Segredo para criptografia AES-256-GCM (mín. 32 chars)  |
| `signingSecret`    | string              | Segredo para assinatura HMAC-SHA256                    |
| `payload`          | Record<string, any> | Dados JSON a serem criptografados no token             |
| `expiresInSeconds` | number              | Tempo de expiração em segundos. Default: 3600 (1 hora) |

### `verifyAccessToken(options)`

Verifica e descriptografa um token de acesso (lança exceções).

```typescript
import { verifyAccessToken } from "serverless-crypto-utils";

try {
  const payloadJson = await verifyAccessToken({
    encryptionSecret: "seu-segredo-de-criptografia-32-chars",
    signingSecret: "seu-segredo-de-assinatura-hmac",
    accessToken: token,
  });

  const payload = JSON.parse(payloadJson);
  console.log("Usuário:", payload.userId);
} catch (error) {
  console.error("Token inválido:", error.message);
}
```

| Parâmetro          | Tipo   | Descrição                                     |
| ------------------ | ------ | --------------------------------------------- |
| `encryptionSecret` | string | Segredo usado para criptografia               |
| `signingSecret`    | string | Segredo usado para assinatura                 |
| `accessToken`      | string | Token no formato `iv.encryptedData.signature` |

### `verifyAccessTokenSafe(options)` (Recomendado)

Verifica e descriptografa um token usando Result Pattern (sem exceções).

```typescript
import { verifyAccessTokenSafe, TokenErrorCode } from "serverless-crypto-utils";

const result = await verifyAccessTokenSafe({
  encryptionSecret: "seu-segredo-de-criptografia-32-chars",
  signingSecret: "seu-segredo-de-assinatura-hmac",
  accessToken: token,
});

if (result.success) {
  const payload = JSON.parse(result.data);
  console.log("Login bem-sucedido:", payload.username);
} else {
  console.log(`Erro ${result.error.code}: ${result.error.message}`);
}
```

| Parâmetro          | Tipo   | Descrição                                     |
| ------------------ | ------ | --------------------------------------------- |
| `encryptionSecret` | string | Segredo usado para criptografia               |
| `signingSecret`    | string | Segredo usado para assinatura                 |
| `accessToken`      | string | Token no formato `iv.encryptedData.signature` |

**Códigos de Erro:**

- `INVALID_FORMAT` - Token malformado
- `SIGNATURE_VERIFICATION_FAILED` - Assinatura inválida
- `TOKEN_EXPIRED` - Token expirado
- `INVALID_JSON` - Payload não é JSON válido
- `DECRYPTION_FAILED` - Erro na descriptografia

## 🔒 Segurança

- Vetor de inicialização (IV) aleatório único por token (12 bytes).
- Criptografia AES-256-GCM para confidencialidade.
- Assinatura HMAC-SHA256 para integridade e autenticidade.
- Expiração automática com timestamp integrado.
- Segredos separados para criptografia e assinatura.

## 📌 Exemplo Completo

```typescript
import {
  createAccessToken,
  verifyAccessTokenSafe,
  TokenErrorCode,
} from "serverless-crypto-utils";

const encryptionSecret = process.env.TOKEN_ENCRYPTION_SECRET;
const signingSecret = process.env.TOKEN_SIGNING_SECRET;

// Criar token
const token = await createAccessToken({
  encryptionSecret,
  signingSecret,
  payload: { userId: 123, role: "admin" },
  expiresInSeconds: 900, // 15 minutos
});

console.log("Token:", token);

// Verificar token
const result = await verifyAccessTokenSafe({
  encryptionSecret,
  signingSecret,
  accessToken: token,
});

if (result.success) {
  const user = JSON.parse(result.data);
  console.log("Acesso autorizado:", user.userId);
} else {
  console.log("Acesso negado:", result.error.message);
}
```

## 💡 Uso com Hono (Cloudflare Workers)

```typescript
import { Hono } from "hono";
import { verifyAccessTokenSafe, TokenErrorCode } from "serverless-crypto-utils";

type Bindings = {
  TOKEN_ENCRYPTION_SECRET: string;
  TOKEN_SIGNING_SECRET: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Middleware de autenticação
const authMiddleware = async (c, next) => {
  const token = c.req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return c.json({ error: "Token obrigatório" }, 401);
  }

  const result = await verifyAccessTokenSafe({
    encryptionSecret: c.env.TOKEN_ENCRYPTION_SECRET,
    signingSecret: c.env.TOKEN_SIGNING_SECRET,
    accessToken: token,
  });

  if (!result.success) {
    const status =
      result.error.code === TokenErrorCode.TOKEN_EXPIRED ? 401 : 403;
    return c.json({ error: result.error.message }, status);
  }

  c.set("user", JSON.parse(result.data));
  await next();
};

// Rota protegida
app.use("/api/protected/*", authMiddleware);
app.get("/api/protected/profile", (c) => {
  const user = c.get("user");
  return c.json({ message: "Perfil do usuário", user });
});

export default app;
```
