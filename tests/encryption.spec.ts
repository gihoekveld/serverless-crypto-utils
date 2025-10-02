import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  encryptObject,
  decryptObject,
  encryptSafe,
  decryptSafe,
  encryptObjectSafe,
  decryptObjectSafe,
  EncryptionErrorCode
} from '../src/encryption';

describe('Encryption', () => {
  const testSecret = 'myTestSecretKey123';
  const testData = 'Hello, World! This is sensitive data.';
  const testObject = {
    name: 'John Doe',
    email: 'john@example.com',
    age: 30,
    metadata: {
      lastLogin: '2024-01-01T00:00:00Z',
      preferences: ['dark-mode', 'notifications']
    }
  };

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt a string successfully', async () => {
      const encrypted = await encrypt(testData, testSecret);
      expect(encrypted).toMatch(/^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/); // Base64.Base64 format
      
      const decrypted = await decrypt(encrypted, testSecret);
      expect(decrypted).toBe(testData);
    });

    it('should produce different encrypted results for the same input', async () => {
      const encrypted1 = await encrypt(testData, testSecret);
      const encrypted2 = await encrypt(testData, testSecret);
      
      expect(encrypted1).not.toBe(encrypted2); // Different IVs should produce different results
      
      const decrypted1 = await decrypt(encrypted1, testSecret);
      const decrypted2 = await decrypt(encrypted2, testSecret);
      
      expect(decrypted1).toBe(testData);
      expect(decrypted2).toBe(testData);
    });

    it('should fail to decrypt with wrong secret', async () => {
      const encrypted = await encrypt(testData, testSecret);
      
      await expect(decrypt(encrypted, 'wrongSecret')).rejects.toThrow();
    });

    it('should fail to decrypt malformed data', async () => {
      await expect(decrypt('invalid.format', testSecret)).rejects.toThrow();
      await expect(decrypt('onlyonepart', testSecret)).rejects.toThrow();
      await expect(decrypt('', testSecret)).rejects.toThrow();
    });

    it('should handle empty data gracefully', async () => {
      await expect(encrypt('', testSecret)).rejects.toThrow('Data to encrypt cannot be empty');
      await expect(decrypt('', testSecret)).rejects.toThrow('Encrypted data cannot be empty');
    });

    it('should handle empty secret gracefully', async () => {
      await expect(encrypt(testData, '')).rejects.toThrow('Encryption secret cannot be empty');
    });

    it('should work with various secret lengths', async () => {
      const secrets = [
        'short',
        'mediumLengthSecret123',
        'veryLongSecretKeyThatIsMoreThan32CharactersLongToTestTruncation',
        '!@#$%^&*()_+-=[]{}|;:,.<>?'
      ];

      for (const secret of secrets) {
        const encrypted = await encrypt(testData, secret);
        const decrypted = await decrypt(encrypted, secret);
        expect(decrypted).toBe(testData);
      }
    });
  });

  describe('encryptObject/decryptObject', () => {
    it('should encrypt and decrypt an object successfully', async () => {
      const encrypted = await encryptObject(testObject, testSecret);
      expect(encrypted).toMatch(/^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/);
      
      const decrypted = await decryptObject<typeof testObject>(encrypted, testSecret);
      expect(decrypted).toEqual(testObject);
    });

    it('should handle various object types', async () => {
      const testCases = [
        { value: 42, type: 'number' },
        { value: true, type: 'boolean' },
        { value: ['a', 'b', 'c'], type: 'array' },
        { value: { nested: { deeply: 'nested' } }, type: 'nested object' }
      ];

      for (const testCase of testCases) {
        const encrypted = await encryptObject(testCase.value, testSecret);
        const decrypted = await decryptObject(encrypted, testSecret);
        expect(decrypted).toEqual(testCase.value);
      }
    });

    it('should fail with null or undefined objects', async () => {
      await expect(encryptObject(null, testSecret)).rejects.toThrow('Object to encrypt cannot be null or undefined');
      await expect(encryptObject(undefined, testSecret)).rejects.toThrow('Object to encrypt cannot be null or undefined');
    });

    it('should fail to decrypt invalid JSON', async () => {
      const malformedJson = await encrypt('invalid json {', testSecret);
      await expect(decryptObject(malformedJson, testSecret)).rejects.toThrow('Failed to parse decrypted data as JSON');
    });
  });

  describe('Safe versions with Result pattern', () => {
    describe('encryptSafe/decryptSafe', () => {
      it('should return success result for valid operations', async () => {
        const encryptResult = await encryptSafe(testData, testSecret);
        expect(encryptResult.success).toBe(true);
        if (encryptResult.success) {
          expect(encryptResult.data).toMatch(/^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/);
          
          const decryptResult = await decryptSafe(encryptResult.data, testSecret);
          expect(decryptResult.success).toBe(true);
          if (decryptResult.success) {
            expect(decryptResult.data).toBe(testData);
          }
        }
      });

      it('should return error result for invalid operations', async () => {
        const result1 = await encryptSafe('', testSecret);
        expect(result1.success).toBe(false);
        if (!result1.success) {
          expect(result1.error.code).toBe(EncryptionErrorCode.ENCRYPTION_FAILED);
          expect(result1.error.message).toBe('Failed to encrypt data');
        }

        const result2 = await decryptSafe('invalid', testSecret);
        expect(result2.success).toBe(false);
        if (!result2.success) {
          expect(result2.error.code).toBe(EncryptionErrorCode.DECRYPTION_FAILED);
          expect(result2.error.message).toBe('Failed to decrypt data');
        }
      });
    });

    describe('encryptObjectSafe/decryptObjectSafe', () => {
      it('should return success result for valid operations', async () => {
        const encryptResult = await encryptObjectSafe(testObject, testSecret);
        expect(encryptResult.success).toBe(true);
        if (encryptResult.success) {
          const decryptResult = await decryptObjectSafe<typeof testObject>(encryptResult.data, testSecret);
          expect(decryptResult.success).toBe(true);
          if (decryptResult.success) {
            expect(decryptResult.data).toEqual(testObject);
          }
        }
      });

      it('should return error result for invalid operations', async () => {
        const result1 = await encryptObjectSafe(null, testSecret);
        expect(result1.success).toBe(false);
        if (!result1.success) {
          expect(result1.error.code).toBe(EncryptionErrorCode.ENCRYPTION_FAILED);
        }

        const result2 = await decryptObjectSafe('invalid', testSecret);
        expect(result2.success).toBe(false);
        if (!result2.success) {
          expect(result2.error.code).toBe(EncryptionErrorCode.DECRYPTION_FAILED);
        }
      });
    });
  });

  describe('Security properties', () => {
    it('should use different IVs for each encryption', async () => {
      const encryptions = await Promise.all([
        encrypt(testData, testSecret),
        encrypt(testData, testSecret),
        encrypt(testData, testSecret)
      ]);

      const ivs = encryptions.map(enc => enc.split('.')[0]);
      const uniqueIvs = new Set(ivs);
      
      expect(uniqueIvs.size).toBe(3); // All IVs should be different
    });

    it('should produce consistent results for same secret', async () => {
      const secret = 'consistentSecret';
      const data = 'consistent data';
      
      const encrypted1 = await encrypt(data, secret);
      const decrypted1 = await decrypt(encrypted1, secret);
      
      const encrypted2 = await encrypt(data, secret);
      const decrypted2 = await decrypt(encrypted2, secret);
      
      expect(decrypted1).toBe(data);
      expect(decrypted2).toBe(data);
      expect(decrypted1).toBe(decrypted2);
    });

    it('should handle Unicode and special characters', async () => {
      const unicodeData = '🔒 Hello 世界! Café naïve résumé 🚀';
      const encrypted = await encrypt(unicodeData, testSecret);
      const decrypted = await decrypt(encrypted, testSecret);
      
      expect(decrypted).toBe(unicodeData);
    });

    it('should handle large data', async () => {
      const largeData = 'x'.repeat(10000); // 10KB of data
      const encrypted = await encrypt(largeData, testSecret);
      const decrypted = await decrypt(encrypted, testSecret);
      
      expect(decrypted).toBe(largeData);
    });
  });

  describe('Edge cases', () => {
    it('should handle very short secrets with padding', async () => {
      const shortSecret = 'a';
      const encrypted = await encrypt(testData, shortSecret);
      const decrypted = await decrypt(encrypted, shortSecret);
      
      expect(decrypted).toBe(testData);
    });

    it('should handle complex nested objects', async () => {
      const complexObject = {
        id: 1,
        user: {
          profile: {
            personal: {
              name: 'John',
              contacts: [
                { type: 'email', value: 'john@test.com' },
                { type: 'phone', value: '+1234567890' }
              ]
            }
          }
        },
        metadata: {
          created: new Date().toISOString(),
          tags: ['tag1', 'tag2', 'tag3'],
          settings: {
            theme: 'dark',
            notifications: {
              email: true,
              push: false,
              sms: null
            }
          }
        }
      };

      const encrypted = await encryptObject(complexObject, testSecret);
      const decrypted = await decryptObject<typeof complexObject>(encrypted, testSecret);
      
      expect(decrypted).toEqual(complexObject);
    });
  });
});