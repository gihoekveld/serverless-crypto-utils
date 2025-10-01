import { it, describe, expect } from 'vitest';
import { ulid, uuidV4 } from '../src/index';

describe('Serverless Crypto Utilities - ID Generation', () => {

  it('should generate a valid ULID', () => {
    const id = ulid();
    expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it('should generate unique ULIDs', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ids.add(ulid());
    }
    expect(ids.size).toBe(1000);
  });

  it('should generate a valid UUID v4', () => {
    const id = uuidV4();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it('should generate unique UUID v4', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ids.add(uuidV4());
    }
    expect(ids.size).toBe(1000);
  });

});