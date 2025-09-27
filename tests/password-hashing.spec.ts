import { it, describe } from 'node:test';
import * as assert from 'node:assert';
import { 
  hashPassword, 
  verifyPassword 
} from '../src/index';
import { toBase64Url } from '../src/utils';

describe('Serverless Crypto Utilities - Password Hashing', () => {
  
  it('should verify password successfully', async () => {
    const stored = await hashPassword("minhaSenhaSecreta");
    const ok = await verifyPassword("minhaSenhaSecreta", stored);

    assert.ok(ok);
  });

  it('should fail to invalid password', async () => {
    const stored = await hashPassword("minhaSenhaSecreta");
    const fail = await verifyPassword("outraSenha", stored);

    assert.ok(!fail);
  });

  it('should concatenate salt with hashed password', async () => {
    const saltBase64 = toBase64Url(new TextEncoder().encode('mySalt').buffer);

    const stored = await hashPassword("minhaSenhaSecreta", {
      saltInBase64Url: saltBase64
    });

    const [, salt, ] = stored.split(".");

    assert.strictEqual(salt, saltBase64);
  });

  it('should concatenate interations with hashed password', async () => {
    const stored = await hashPassword("minhaSenhaSecreta", {
      iterations: 500000
    });

    const [iterations, , ] = stored.split(".");

    assert.strictEqual(iterations, "500000");
  });

  it('should fail if iterations is less than 1000', async () => {
    await assert.rejects(async () => {
      await hashPassword("minhaSenhaSecreta", {
        iterations: 500
      });
    }, {
      message: "Iterations must be at least 1000"
    })
  });

  it('should fail if iterations is more than 1000000', async () => {
    await assert.rejects(async () => {
      await hashPassword("minhaSenhaSecreta", {
        iterations: 1500000
      });
    }, {
      message: "Iterations must be at most 1000000"
    })
  });

  it('should verify password with pepper successfully', async () => {
    const stored = await hashPassword("minhaSenhaSecreta", {  
      pepper: "myPepper"
    });

    const ok = await verifyPassword("minhaSenhaSecreta", stored, {
      pepper: "myPepper"
    });

    assert.ok(ok);
  });

  it('should fail if pepper is incorrect', async () => {
    const stored = await hashPassword("minhaSenhaSecreta", {
      pepper: "myPepper"
    });

    const fail = await verifyPassword("minhaSenhaSecreta", stored, {
      pepper: "wrongPepper"
    });

    assert.ok(!fail);
  })
});