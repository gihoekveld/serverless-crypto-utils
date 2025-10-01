import { it, describe, expect } from 'vitest';
import { 
  hashPassword, 
  verifyPassword 
} from '../src/index';
import { toBase64Url } from '../src/utils';

describe('Serverless Crypto Utilities - Password Hashing', () => {
  
  it('should verify password successfully', async () => {
    const stored = await hashPassword("minhaSenhaSecreta");
    const ok = await verifyPassword("minhaSenhaSecreta", stored);

    expect(ok).toBeTruthy();
  });

  it('should fail to invalid password', async () => {
    const stored = await hashPassword("minhaSenhaSecreta");
    const fail = await verifyPassword("outraSenha", stored);

    expect(fail).toBeFalsy();
  });

  it('should concatenate salt with hashed password', async () => {
    const saltBase64 = toBase64Url(new TextEncoder().encode('mySalt').buffer);

    const stored = await hashPassword("minhaSenhaSecreta", {
      saltInBase64Url: saltBase64
    });

    const [, salt, ] = stored.split(".");

    expect(salt).toBe(saltBase64);
  });

  it('should concatenate interations with hashed password', async () => {
    const stored = await hashPassword("minhaSenhaSecreta", {
      iterations: 500000
    });

    const [iterations, , ] = stored.split(".");

    expect(iterations).toBe("500000");
  });

  it('should fail if iterations is less than 1000', async () => {
    await expect(async () => {
      await hashPassword("minhaSenhaSecreta", {
        iterations: 500
      });
    }).rejects.toThrow("Iterations must be at least 1000");
  });

  it('should fail if iterations is more than 1000000', async () => {
    await expect(async () => {
      await hashPassword("minhaSenhaSecreta", {
        iterations: 1500000
      });
    }).rejects.toThrow("Iterations must be at most 1000000");
  });

  it('should verify password with pepper successfully', async () => {
    const stored = await hashPassword("minhaSenhaSecreta", {  
      pepper: "myPepper"
    });

    const ok = await verifyPassword("minhaSenhaSecreta", stored, {
      pepper: "myPepper"
    });

    expect(ok).toBeTruthy();
  });

  it('should fail if pepper is incorrect', async () => {
    const stored = await hashPassword("minhaSenhaSecreta", {
      pepper: "myPepper"
    });

    const fail = await verifyPassword("minhaSenhaSecreta", stored, {
      pepper: "wrongPepper"
    });

    expect(fail).toBeFalsy();
  })
});