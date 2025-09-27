const ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Base32 Crockford, sem I,L,O,U

const encodeBase32 = (value: number, length: number): string => {
  let str = '';
  for (let i = 0; i < length; i++) {
    str = ENCODING[value % 32] + str;
    value = Math.floor(value / 32);
  }
  return str;
};

/**
 * Generate a ULID (Universally Unique Lexicographically Sortable Identifier).
 * 
 * @returns {string} A new ULID string.
 * @example
 * const id = ulid();
 * console.log(id); // e.g., "01ARZ3NDEKTSV4RRFFQ69G5FAV"
 */
export const ulid = (): string => {
  const randomInt = (max: number): number => Math.floor(Math.random() * max);

  const timestamp = Date.now();
  const timestampStr = encodeBase32(timestamp, 10);

  let randomStr = '';
  for (let i = 0; i < 16; i++) {
    randomStr += ENCODING[randomInt(32)];
  }

  return timestampStr + randomStr;
}

/**
 * Generate a UUID v4 (Universally Unique Identifier version 4).
 * 
 * @returns {string} A new UUID v4 string.
 * @example
 * const id = uuidV4();
 * console.log(id); // e.g., "3b12f1df-5232-4e6c-8a5a-3b8c9f1e6f7d"
 */
export const uuidV4 = (): string => {
  return crypto.randomUUID()
}