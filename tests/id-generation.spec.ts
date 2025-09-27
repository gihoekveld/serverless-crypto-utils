import { it, describe } from 'node:test';
import * as assert from 'node:assert';

import {ulid, uuidV4} from '../src/index'

describe('Serverless Crypto Utilities - ID Generation', () => {

  it('should generate a valid ULID', () => {
    const id = ulid();
    assert.match(id, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it('should generate unique ULIDs', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ids.add(ulid());
    }
    assert.strictEqual(ids.size, 1000);
  });

  it('should generate a valid UUID v4', () => {
    const id = uuidV4();
    assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it('should generate unique UUID v4', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ids.add(uuidV4());
    }
    assert.strictEqual(ids.size, 1000);
  });

});