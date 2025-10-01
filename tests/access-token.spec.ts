import { it, describe, beforeEach } from 'node:test';
import * as assert from 'node:assert';
import { 
  createAccessToken, 
  verifyAccessToken,
  verifyAccessTokenSafe,
  TokenErrorCode,
  type TokenResult
} from '../src/access-token';

describe('Serverless Crypto Utilities - Access Token', () => {
  let encryptionSecret: string;
  let signingSecret: string;
  let testPayload: Record<string, any>;

  beforeEach(() => {
    encryptionSecret = 'test-encryption-secret-32-chars-min';
    signingSecret = 'test-signing-secret-for-hmac-256';
    testPayload = {
      userId: 12345,
      username: 'testuser',
      role: 'admin',
      permissions: ['read', 'write', 'delete']
    };
  });

  describe('createAccessToken', () => {
    it('should create a valid access token with default expiration', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      // Token should have 3 parts separated by dots (iv.encryptedData.signature)
      const parts = token.split('.');
      assert.strictEqual(parts.length, 3, 'Token should have 3 parts');

      // Each part should be base64 encoded
      parts.forEach((part, index) => {
        assert.ok(part.length > 0, `Part ${index} should not be empty`);
        assert.ok(/^[A-Za-z0-9+/]*={0,2}$/.test(part), `Part ${index} should be valid base64`);
      });
    });

    it('should create tokens with different IVs for same payload', async () => {
      const token1 = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      const token2 = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      // Tokens should be different due to random IV
      assert.notStrictEqual(token1, token2, 'Tokens should be different due to random IV');

      // But both should be valid and contain the same core payload data
      const payload1 = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token1
      });
      
      const payload2 = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token2
      });

      const parsed1 = JSON.parse(payload1);
      const parsed2 = JSON.parse(payload2);

      // Compare core payload data (excluding timestamp which may differ by milliseconds)
      assert.strictEqual(parsed1.userId, parsed2.userId);
      assert.strictEqual(parsed1.username, parsed2.username);
      assert.strictEqual(parsed1.role, parsed2.role);
      assert.deepStrictEqual(parsed1.permissions, parsed2.permissions);
    });

    it('should create token with custom expiration time', async () => {
      const customExpirationSeconds = 7200; // 2 hours
      const beforeCreation = Date.now();

      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload,
        expiresInSeconds: customExpirationSeconds
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      const parsedPayload = JSON.parse(decryptedPayload);
      const expirationTime = new Date(parsedPayload.expiresAt).getTime();
      const expectedExpiration = beforeCreation + (customExpirationSeconds * 1000);

      // Allow 1 second tolerance for execution time
      assert.ok(
        Math.abs(expirationTime - expectedExpiration) < 1000,
        'Token should expire at the specified time'
      );
    });

    it('should include original payload data in token', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      const parsedPayload = JSON.parse(decryptedPayload);

      assert.strictEqual(parsedPayload.userId, testPayload.userId);
      assert.strictEqual(parsedPayload.username, testPayload.username);
      assert.strictEqual(parsedPayload.role, testPayload.role);
      assert.deepStrictEqual(parsedPayload.permissions, testPayload.permissions);
      assert.ok(parsedPayload.expiresAt, 'Should include expiration timestamp');
    });
  });

  describe('verifyAccessToken (with exceptions)', () => {
    it('should verify and decrypt a valid token', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      const parsedPayload = JSON.parse(decryptedPayload);
      assert.strictEqual(parsedPayload.userId, testPayload.userId);
    });

    it('should throw error for invalid token format', async () => {
      await assert.rejects(async () => {
        await verifyAccessToken({
          encryptionSecret,
          signingSecret,
          accessToken: 'invalid.token'
        });
      }, {
        message: 'Invalid access token format: expected 3 parts separated by dots'
      });
    });

    it('should throw error for token with wrong encryption secret', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      await assert.rejects(async () => {
        await verifyAccessToken({
          encryptionSecret: 'wrong-encryption-secret-32-chars',
          signingSecret,
          accessToken: token
        });
      });
    });

    it('should throw error for token with wrong signing secret', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      await assert.rejects(async () => {
        await verifyAccessToken({
          encryptionSecret,
          signingSecret: 'wrong-signing-secret-for-hmac',
          accessToken: token
        });
      }, {
        message: 'Invalid access token: signature verification failed'
      });
    });

    it('should throw error for expired token', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload,
        expiresInSeconds: -1 // Already expired
      });

      await assert.rejects(async () => {
        await verifyAccessToken({
          encryptionSecret,
          signingSecret,
          accessToken: token
        });
      }, {
        message: 'Access token has expired'
      });
    });

    it('should throw error for malformed base64 in token', async () => {
      const invalidToken = 'invalid-base64!.another-invalid-base64!.signature!';

      await assert.rejects(async () => {
        await verifyAccessToken({
          encryptionSecret,
          signingSecret,
          accessToken: invalidToken
        });
      });
    });
  });

  describe('verifyAccessTokenSafe (with Result pattern)', () => {
    it('should return success result for valid token', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      assert.ok(result.success, 'Result should be successful');
      if (result.success) {
        const parsedPayload = JSON.parse(result.data);
        assert.strictEqual(parsedPayload.userId, testPayload.userId);
      }
    });

    it('should return error result for invalid token format', async () => {
      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: 'invalid.token'
      });

      assert.ok(!result.success, 'Result should be unsuccessful');
      if (!result.success) {
        assert.strictEqual(result.error.code, TokenErrorCode.INVALID_FORMAT);
        assert.strictEqual(result.error.details?.partsFound, 2);
        assert.strictEqual(result.error.details?.expected, 3);
      }
    });

    it('should return error result for signature verification failure', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret: 'wrong-signing-secret-for-hmac',
        accessToken: token
      });

      assert.ok(!result.success, 'Result should be unsuccessful');
      if (!result.success) {
        assert.strictEqual(result.error.code, TokenErrorCode.SIGNATURE_VERIFICATION_FAILED);
      }
    });

    it('should return error result for expired token', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload,
        expiresInSeconds: -1
      });

      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      assert.ok(!result.success, 'Result should be unsuccessful');
      if (!result.success) {
        assert.strictEqual(result.error.code, TokenErrorCode.TOKEN_EXPIRED);
        assert.ok(result.error.details?.expiredAt, 'Should include expiration details');
        assert.ok(result.error.details?.currentTime, 'Should include current time');
      }
    });

    it('should return error result for decryption failure', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      const result = await verifyAccessTokenSafe({
        encryptionSecret: 'wrong-encryption-secret-32-chars',
        signingSecret,
        accessToken: token
      });

      assert.ok(!result.success, 'Result should be unsuccessful');
      if (!result.success) {
        assert.strictEqual(result.error.code, TokenErrorCode.DECRYPTION_FAILED);
      }
    });

    it('should return error result for invalid JSON payload', async () => {
      // Create a token manually with invalid JSON
      const invalidToken = 'dGVzdA==.aW52YWxpZCBqc29u.dGVzdA=='; // base64 encoded but invalid structure

      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: invalidToken
      });

      assert.ok(!result.success, 'Result should be unsuccessful');
      if (!result.success) {
        // Could be DECRYPTION_FAILED or INVALID_JSON depending on implementation
        assert.ok([
          TokenErrorCode.DECRYPTION_FAILED,
          TokenErrorCode.INVALID_JSON
        ].includes(result.error.code as TokenErrorCode));
      }
    });
  });

  describe('Token security properties', () => {
    it('should produce different signatures for different payloads', async () => {
      const payload1 = { userId: 123 };
      const payload2 = { userId: 456 };

      const token1 = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: payload1
      });

      const token2 = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: payload2
      });

      // Extract signatures (last part)
      const signature1 = token1.split('.')[2];
      const signature2 = token2.split('.')[2];

      assert.notStrictEqual(signature1, signature2, 'Different payloads should have different signatures');
    });

    it('should produce different encrypted data for same payload (due to random IV)', async () => {
      const token1 = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      const token2 = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      // Extract IV and encrypted data (first two parts)
      const [iv1, encrypted1] = token1.split('.');
      const [iv2, encrypted2] = token2.split('.');

      assert.notStrictEqual(iv1, iv2, 'IVs should be different');
      assert.notStrictEqual(encrypted1, encrypted2, 'Encrypted data should be different due to different IVs');
    });

    it('should fail with tampered token data', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      // Tamper with the encrypted data part
      const parts = token.split('.');
      const tamperedToken = `${parts[0]}.${parts[1].slice(0, -4)}XXXX.${parts[2]}`;

      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: tamperedToken
      });

      assert.ok(!result.success, 'Tampered token should fail verification');
    });
  });

  describe('Edge cases and error conditions', () => {
    it('should handle empty payload', async () => {
      const emptyPayload = {};
      
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: emptyPayload
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      const parsedPayload = JSON.parse(decryptedPayload);
      assert.ok(parsedPayload.expiresAt, 'Should still include expiration');
    });

    it('should handle payload with special characters', async () => {
      const specialPayload = {
        message: 'Hello 🌍! Special chars: áéíóú ñç @#$%^&*()',
        unicode: '日本語 العربية русский',
        symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
      };

      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: specialPayload
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      const parsedPayload = JSON.parse(decryptedPayload);
      assert.strictEqual(parsedPayload.message, specialPayload.message);
      assert.strictEqual(parsedPayload.unicode, specialPayload.unicode);
      assert.strictEqual(parsedPayload.symbols, specialPayload.symbols);
    });

    it('should handle different encryption secrets', async () => {
      const alternativeSecret = 'alternative-encryption-secret-32';

      // Should work with different secret
      const token = await createAccessToken({
        encryptionSecret: alternativeSecret,
        signingSecret,
        payload: testPayload
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret: alternativeSecret,
        signingSecret,
        accessToken: token
      });

      const parsedPayload = JSON.parse(decryptedPayload);
      assert.strictEqual(parsedPayload.userId, testPayload.userId);
    });

    it('should handle very short encryption secret by padding with zeros', async () => {
      const shortSecret = 'short'; // Less than 32 chars

      // Should work by padding the key material with zeros
      const token = await createAccessToken({
        encryptionSecret: shortSecret,
        signingSecret,
        payload: testPayload
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret: shortSecret,
        signingSecret,
        accessToken: token
      });

      const parsedPayload = JSON.parse(decryptedPayload);
      assert.strictEqual(parsedPayload.userId, testPayload.userId);
    });
  });
});