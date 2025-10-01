import { it, describe, beforeEach, expect } from 'vitest';
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
      expect(parts.length).toBe(3);

      // Each part should be base64 encoded
      parts.forEach((part, index) => {
        expect(part.length).toBeGreaterThan(0);
        expect(part).toMatch(/^[A-Za-z0-9+/]*={0,2}$/);
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
      expect(token1).not.toBe(token2);

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
      expect(parsed1.userId).toBe(parsed2.userId);
      expect(parsed1.username).toBe(parsed2.username);
      expect(parsed1.role).toBe(parsed2.role);
      expect(parsed1.permissions).toEqual(parsed2.permissions);
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
      expect(
        Math.abs(expirationTime - expectedExpiration) < 1000
      ).toBeTruthy();
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

      expect(parsedPayload.userId).toBe(testPayload.userId);
      expect(parsedPayload.username).toBe(testPayload.username);
      expect(parsedPayload.role).toBe(testPayload.role);
      expect(parsedPayload.permissions).toEqual(testPayload.permissions);
      expect(parsedPayload.expiresAt).toBeTruthy();
    });

    it('should create token with shorter expiration when specified', async () => {
      const shortExpirationSeconds = 1; // 1 second
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload,
        expiresInSeconds: shortExpirationSeconds
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      const parsedPayload = JSON.parse(decryptedPayload);
      expect(parsedPayload.userId).toBe(testPayload.userId);

      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      await expect(async () => {
        await verifyAccessToken({
          encryptionSecret,
          signingSecret,
          accessToken: token
        });
      }).rejects.toThrow();
    });

    it('should handle short encryption secret gracefully', async () => {
      // The function doesn't validate secret length, it pads with zeros
      const token = await createAccessToken({
        encryptionSecret: 'short', // This will be padded
        signingSecret,
        payload: testPayload
      });

      // Token should still be created but may not be as secure
      expect(token).toBeTruthy();
      expect(token.split('.')).toHaveLength(3);
    });

    it('should handle short signing secret gracefully', async () => {
      // The function doesn't validate secret length
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret: 'short', // This will still work
        payload: testPayload
      });

      // Token should still be created
      expect(token).toBeTruthy();
      expect(token.split('.')).toHaveLength(3);
    });

    it('should handle negative expiration', async () => {
      // Negative expiration creates a token that's already expired
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload,
        expiresInSeconds: -1 // Creates immediately expired token
      });

      // Token should be created but immediately expired
      expect(token).toBeTruthy();
      
      // Try to verify - should fail due to expiration
      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(TokenErrorCode.TOKEN_EXPIRED);
      }
    });

    it('should handle zero expiration', async () => {
      // Zero expiration creates a token that may or may not be immediately expired
      // depending on timing precision
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload,
        expiresInSeconds: 0 // Creates immediately expired token
      });

      // Token should be created
      expect(token).toBeTruthy();
      
      // Add a small delay to ensure expiration
      await new Promise(resolve => setTimeout(resolve, 10));
      
      // Try to verify - should fail due to expiration
      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(TokenErrorCode.TOKEN_EXPIRED);
      }
    });
  });

  describe('verifyAccessToken', () => {
    it('should successfully verify valid token', async () => {
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
      expect(parsedPayload.userId).toBe(testPayload.userId);
    });
  });

  describe('verifyAccessTokenSafe', () => {
    it('should return successful result for valid token', async () => {
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

      expect(result.success).toBe(true);
      if (result.success) {
        const parsedPayload = JSON.parse(result.data);
        expect(parsedPayload.userId).toBe(testPayload.userId);
      }
    });

    it('should return error for invalid token format', async () => {
      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: 'invalid.token' // Only 2 parts instead of 3
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(TokenErrorCode.INVALID_FORMAT);
        expect(result.error.details?.partsFound).toBe(2);
        expect(result.error.details?.expected).toBe(3);
      }
    });

    it('should return error for invalid signature', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret: 'different-signing-secret-hmac256',
        accessToken: token
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(TokenErrorCode.SIGNATURE_VERIFICATION_FAILED);
      }
    });

    it('should return error for expired token', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload,
        expiresInSeconds: 1 // 1 second
      });

      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(TokenErrorCode.TOKEN_EXPIRED);
        expect(result.error.details?.expiredAt).toBeTruthy();
        expect(result.error.details?.currentTime).toBeTruthy();
      }
    });

    it('should return error for wrong encryption secret', async () => {
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

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(TokenErrorCode.DECRYPTION_FAILED);
      }
    });

    it('should return error for malformed token data', async () => {
      // Create a token with properly formed structure but invalid base64 data
      const fakeToken = 'dGVzdA==.aW52YWxpZA==.c2lnbmF0dXJl';

      const result = await verifyAccessTokenSafe({
        encryptionSecret,
        signingSecret,
        accessToken: fakeToken
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect([
          TokenErrorCode.DECRYPTION_FAILED,
          TokenErrorCode.SIGNATURE_VERIFICATION_FAILED,
          TokenErrorCode.INVALID_FORMAT
        ]).toContain(result.error.code);
      }
    });
  });

  describe('Token Security Properties', () => {
    it('should generate different signatures for different payloads', async () => {
      const token1 = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: { userId: 1 }
      });

      const token2 = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: { userId: 2 }
      });

      const signature1 = token1.split('.')[2];
      const signature2 = token2.split('.')[2];

      expect(signature1).not.toBe(signature2);
    });

    it('should not decrypt with wrong encryption key', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      await expect(async () => {
        await verifyAccessToken({
          encryptionSecret: 'different-encryption-key-32-chars',
          signingSecret,
          accessToken: token
        });
      }).rejects.toThrow();
    });

    it('should not verify with wrong signing key', async () => {
      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: testPayload
      });

      await expect(async () => {
        await verifyAccessToken({
          encryptionSecret,
          signingSecret: 'different-signing-key-for-hmac256',
          accessToken: token
        });
      }).rejects.toThrow();
    });

    it('should handle concurrent token operations', async () => {
      const promises = Array.from({ length: 10 }, async (_, i) => {
        const token = await createAccessToken({
          encryptionSecret,
          signingSecret,
          payload: { ...testPayload, iteration: i }
        });

        const decryptedPayload = await verifyAccessToken({
          encryptionSecret,
          signingSecret,
          accessToken: token
        });

        const parsed = JSON.parse(decryptedPayload);
        expect(parsed.iteration).toBe(i);
        return parsed;
      });

      const results = await Promise.all(promises);
      expect(results).toHaveLength(10);

      // Verify each result has the correct iteration number
      results.forEach((result, index) => {
        expect(result.iteration).toBe(index);
      });
    });

    it('should handle large payloads', async () => {
      const largePayload = {
        ...testPayload,
        data: Array.from({ length: 1000 }, (_, i) => `item-${i}`),
        metadata: {
          description: 'A'.repeat(1000),
          tags: Array.from({ length: 100 }, (_, i) => `tag-${i}`)
        }
      };

      const token = await createAccessToken({
        encryptionSecret,
        signingSecret,
        payload: largePayload
      });

      const decryptedPayload = await verifyAccessToken({
        encryptionSecret,
        signingSecret,
        accessToken: token
      });

      const parsed = JSON.parse(decryptedPayload);
      expect(parsed.data).toHaveLength(1000);
      expect(parsed.metadata.description).toHaveLength(1000);
      expect(parsed.metadata.tags).toHaveLength(100);
    });

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

      const parsed = JSON.parse(decryptedPayload);
      // Should still have the expiresAt field even with empty payload
      expect(parsed.expiresAt).toBeTruthy();
    });

    it('should handle special characters in payload', async () => {
      const specialPayload = {
        username: 'user@domain.com',
        description: 'Special chars: àáâãäåæçèéêë 中文 🚀 ñ ü',
        symbols: '!@#$%^&*()_+-={}[]|\\:";\'<>?,./',
        unicode: '🌟✨💫⭐🎯🔥💎🚀🎪🎨'
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

      const parsed = JSON.parse(decryptedPayload);
      expect(parsed.username).toBe(specialPayload.username);
      expect(parsed.description).toBe(specialPayload.description);
      expect(parsed.symbols).toBe(specialPayload.symbols);
      expect(parsed.unicode).toBe(specialPayload.unicode);
    });
  });
});