/**
 * @dicsussion/crypto — BN254 Scalar Field
 *
 * Canonical field element encoding and validation per RFC 003 §3.3.
 *
 * Every scalar `v` handed to a Circom/BN254 routine MUST satisfy
 * `0 ≤ v < r`. Non-canonical encodings are rejected *before* hashing or
 * verification, never silently reduced — a value that wraps would let a
 * caller present two distinct encodings of the same field element.
 */

/** BN254 scalar field modulus r (~2^254). */
export const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Byte width of a canonical field element. */
export const FIELD_BYTES = 32;

/** Raised when a value falls outside the canonical field range. */
export class NonCanonicalFieldError extends Error {
  constructor(value: bigint) {
    super(
      `NonCanonicalField: value must satisfy 0 <= v < r, got ${value.toString()}`,
    );
    this.name = 'NonCanonicalFieldError';
  }
}

/** Whether `value` is a canonical BN254 scalar. */
export function isCanonicalField(value: bigint): boolean {
  return value >= 0n && value < BN254_SCALAR_FIELD;
}

/**
 * Assert that `value` is a canonical BN254 scalar.
 *
 * @throws NonCanonicalFieldError if `v >= r` or `v < 0`.
 */
export function assertCanonicalField(value: bigint): bigint {
  if (!isCanonicalField(value)) {
    throw new NonCanonicalFieldError(value);
  }
  return value;
}

/**
 * Encode a field element as 32 big-endian bytes.
 *
 * Fixed-width big-endian is what makes the lexicographic byte ordering
 * required by RFC 002 §4.1 coincide with numeric ordering.
 *
 * @throws NonCanonicalFieldError if the value is out of range.
 */
export function fieldToBytes(value: bigint): Uint8Array {
  assertCanonicalField(value);

  const bytes = new Uint8Array(FIELD_BYTES);
  let remaining = value;

  for (let i = FIELD_BYTES - 1; i >= 0; i--) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }

  return bytes;
}

/**
 * Decode 32 big-endian bytes into a field element.
 *
 * @throws If the buffer is the wrong length or decodes outside the field.
 */
export function bytesToField(bytes: Uint8Array): bigint {
  if (bytes.length !== FIELD_BYTES) {
    throw new Error(
      `Field element must be ${FIELD_BYTES} bytes, got ${bytes.length}`,
    );
  }

  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }

  return assertCanonicalField(value);
}

/**
 * Reduce arbitrary bytes into the field.
 *
 * Used only where the input is a hash digest with no canonical meaning
 * of its own (e.g. mapping SHA-256 output into the field). Never use
 * this to "fix up" a value that was supposed to already be canonical.
 */
export function reduceToField(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value % BN254_SCALAR_FIELD;
}

/**
 * Compare two field elements by their canonical big-endian byte encoding.
 *
 * RFC 002 §4.1 specifies lexicographic ordering over raw bytes. With
 * fixed-width big-endian that is identical to numeric ordering; the
 * comparison is written over bytes to match the spec literally.
 *
 * @returns Negative if a < b, positive if a > b, zero if equal.
 */
export function compareFieldBytes(a: bigint, b: bigint): number {
  const left = fieldToBytes(a);
  const right = fieldToBytes(b);

  for (let i = 0; i < FIELD_BYTES; i++) {
    if (left[i] !== right[i]) return left[i]! - right[i]!;
  }

  return 0;
}

// ─── Modular arithmetic over the scalar field ────────────────────────────────

/** Reduce a possibly-negative integer into `[0, r)`. */
export function fieldMod(value: bigint): bigint {
  const reduced = value % BN254_SCALAR_FIELD;
  return reduced < 0n ? reduced + BN254_SCALAR_FIELD : reduced;
}

/** `(a + b) mod r` */
export function fieldAdd(a: bigint, b: bigint): bigint {
  return fieldMod(a + b);
}

/** `(a - b) mod r` */
export function fieldSub(a: bigint, b: bigint): bigint {
  return fieldMod(a - b);
}

/** `(a * b) mod r` */
export function fieldMul(a: bigint, b: bigint): bigint {
  return fieldMod(a * b);
}

/**
 * Multiplicative inverse via Fermat's little theorem: `a^(r-2) mod r`.
 *
 * The field modulus is prime, so this is well defined for every non-zero
 * element. Exponentiation is constant-time with respect to `a`, which
 * matters because this runs on secret-derived values during slashing.
 *
 * @throws If `a ≡ 0`, which has no inverse.
 */
export function fieldInverse(a: bigint): bigint {
  const base = fieldMod(a);
  if (base === 0n) {
    throw new Error('Zero has no multiplicative inverse in the scalar field');
  }

  let result = 1n;
  let b = base;
  let exponent = BN254_SCALAR_FIELD - 2n;

  while (exponent > 0n) {
    if (exponent & 1n) result = (result * b) % BN254_SCALAR_FIELD;
    b = (b * b) % BN254_SCALAR_FIELD;
    exponent >>= 1n;
  }

  return result;
}

/** `(a / b) mod r`, i.e. `a * b^-1`. */
export function fieldDiv(a: bigint, b: bigint): bigint {
  return fieldMul(a, fieldInverse(b));
}

/** Render a field element as a 0x-prefixed 64-hex-digit string. */
export function fieldToHex(value: bigint): string {
  return `0x${assertCanonicalField(value).toString(16).padStart(FIELD_BYTES * 2, '0')}`;
}

/** Parse a hex string (with or without 0x) into a field element. */
export function hexToField(hex: string): bigint {
  const normalised = hex.startsWith('0x') || hex.startsWith('0X')
    ? hex.slice(2)
    : hex;

  if (normalised.length === 0 || !/^[0-9a-fA-F]+$/.test(normalised)) {
    throw new Error(`Invalid field hex string: ${hex}`);
  }

  return assertCanonicalField(BigInt(`0x${normalised}`));
}
