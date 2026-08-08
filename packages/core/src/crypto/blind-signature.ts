/**
 * @dicsussion/crypto — Chaumian RSA-FDH Blind Signatures
 *
 * Unlinkable voucher issuance per RFC 003 §3.0 and §5.
 *
 * Protocol:
 *   1. Receiver picks serial `s` and computes `m = FDH(s) mod n`.
 *   2. Receiver picks blinding factor `r`, sends `B = m · r^e mod n`.
 *   3. Issuer signs blindly: `S' = B^d mod n` — it never sees `m` or `s`.
 *   4. Receiver unblinds: `S = S' · r^-1 mod n`.
 *   5. Anyone verifies: `S^e ≡ FDH(s) (mod n)`.
 *
 * The issuer cannot correlate the blinded request it signed with the
 * unblinded voucher presented later, which is what keeps the endorsement
 * edge A → B hidden.
 *
 * SECURITY NOTES
 * - Full-domain hashing is mandatory. Blind-signing a raw message would
 *   let a receiver exploit RSA's multiplicative homomorphism to forge a
 *   second signature from one issuance.
 * - A blind-signing key MUST NOT be reused for ordinary signatures. The
 *   issuer signs whatever it is handed, so any other use of the same key
 *   becomes a forgery oracle.
 */

import { sha256 } from '@noble/hashes/sha2.js';

/** Domain-separation label for the full-domain hash. */
const FDH_LABEL = new TextEncoder().encode('dicsussion/voucher-fdh/v1');

/** Frozen RSA modulus size (RFC 003 §3.0). */
export const RSA_MODULUS_BITS = 2048;

/** Modulus size in bytes. */
export const RSA_MODULUS_BYTES = RSA_MODULUS_BITS / 8;

/** Public half of an issuer's blind-signing key. */
export interface BlindPublicKey {
  /** RSA modulus n. */
  readonly n: bigint;
  /** Public exponent e. */
  readonly e: bigint;
}

/** Full issuer key, including the private exponent. */
export interface BlindKeyPair extends BlindPublicKey {
  /** Private exponent d. */
  readonly d: bigint;
}

/** A blinded request plus the secret needed to unblind the response. */
export interface BlindedMessage {
  /** Value sent to the issuer: `m · r^e mod n`. */
  readonly blinded: bigint;
  /** Blinding factor r — never leaves the receiver. */
  readonly blindingFactor: bigint;
}

/**
 * Modular exponentiation by square-and-multiply.
 *
 * **Not constant-time.** The loop branches on the bits of the exponent,
 * so timing and cache behaviour leak information about it — the classic
 * RSA side-channel.
 *
 * Accepted here because of where this runs: `blindSign` executes on the
 * issuer's own device, against a value the issuer chose, with no remote
 * party able to time it. The one exponentiation an attacker *can*
 * influence is `verifyBlindSignature`, which uses only the public
 * exponent `e` — nothing secret to leak.
 *
 * This assumption breaks the moment signing moves to a server, or an
 * attacker can measure local execution (a shared host, a malicious
 * co-resident process). Either change means replacing this with a
 * constant-time ladder.
 */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;

  let result = 1n;
  let b = base % modulus;
  let e = exponent;

  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }

  return result;
}

/**
 * Modular inverse via the extended Euclidean algorithm.
 *
 * @throws If `value` is not invertible modulo `modulus`.
 */
export function modInverse(value: bigint, modulus: bigint): bigint {
  let [old_r, r] = [((value % modulus) + modulus) % modulus, modulus];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }

  if (old_r !== 1n) {
    throw new Error('Value is not invertible modulo the given modulus');
  }

  return ((old_s % modulus) + modulus) % modulus;
}

/** Greatest common divisor. */
function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;

  while (y) {
    [x, y] = [y, x % y];
  }

  return x;
}

/**
 * Generate an RSA-2048 blind-signing keypair.
 *
 * Slow — hundreds of milliseconds to seconds, because keygen searches
 * for two 1024-bit primes and the search time is unbounded in the worst
 * case. Generate once per identity and persist; never per voucher, and
 * never on a path a user is waiting on.
 *
 * Async because Web Crypto's `generateKey` is, and Web Crypto is what
 * makes this work on Node, browsers and React Native alike. `RSA-PSS` is
 * named only to satisfy the API — the key is used for raw FDH blind
 * signing (§5), never for PSS itself.
 */
export async function generateBlindKeyPair(): Promise<BlindKeyPair> {
  const { privateKey } = await globalThis.crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: RSA_MODULUS_BITS,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const jwk = (await globalThis.crypto.subtle.exportKey('jwk', privateKey)) as {
    n?: string;
    e?: string;
    d?: string;
  };

  if (!jwk.n || !jwk.e || !jwk.d) {
    throw new Error('Web Crypto returned an RSA key without n, e or d');
  }

  return {
    n: base64UrlToBigInt(jwk.n),
    e: base64UrlToBigInt(jwk.e),
    d: base64UrlToBigInt(jwk.d),
  };
}

/** Strip the private exponent, leaving a publishable key. */
export function toPublicKey(keypair: BlindKeyPair): BlindPublicKey {
  return { n: keypair.n, e: keypair.e };
}

/**
 * Full-domain hash of a serial into `Z_n`.
 *
 * Expands SHA-256 with an MGF1-style counter construction to one byte
 * beyond the modulus width, then reduces. Hashing to the full domain is
 * what prevents the one-more-forgery attack described above.
 *
 * @param serial Arbitrary-length serial bytes.
 * @param n The issuer's modulus.
 */
export function fullDomainHash(serial: Uint8Array, n: bigint): bigint {
  const targetBytes = RSA_MODULUS_BYTES + 8;
  const label = FDH_LABEL;

  const expanded = new Uint8Array(Math.ceil(targetBytes / 32) * 32);

  for (let counter = 0; counter * 32 < targetBytes; counter++) {
    const block = new Uint8Array(label.length + 4 + serial.length);
    block.set(label, 0);
    // Counter big-endian, matching the MGF1 construction.
    block[label.length] = (counter >>> 24) & 0xff;
    block[label.length + 1] = (counter >>> 16) & 0xff;
    block[label.length + 2] = (counter >>> 8) & 0xff;
    block[label.length + 3] = counter & 0xff;
    block.set(serial, label.length + 4);

    expanded.set(sha256(block), counter * 32);
  }

  let value = 0n;
  for (const byte of expanded.subarray(0, targetBytes)) {
    value = (value << 8n) | BigInt(byte);
  }

  // Reduce into the group, avoiding the degenerate 0 element.
  const reduced = value % n;
  return reduced === 0n ? 1n : reduced;
}

/** Generate a random voucher serial. */
export function generateSerial(byteLength = 32): Uint8Array {
  const serial = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(serial);
  return serial;
}

/**
 * Blind a serial for submission to an issuer.
 *
 * @param serial The receiver's secret serial.
 * @param publicKey The issuer's public key.
 */
export function blind(
  serial: Uint8Array,
  publicKey: BlindPublicKey,
): BlindedMessage {
  const { n, e } = publicKey;
  const message = fullDomainHash(serial, n);

  // r must be invertible mod n; retry on the (vanishingly rare) collision.
  let r: bigint;
  do {
    r = randomBigIntBelow(n);
  } while (r < 2n || gcd(r, n) !== 1n);

  const blinded = (message * modPow(r, e, n)) % n;

  return { blinded, blindingFactor: r };
}

/**
 * Sign a blinded value.
 *
 * The issuer learns nothing about the underlying serial. It MUST apply
 * its own quota accounting before calling this — the signature itself
 * carries no rate limit.
 */
export function blindSign(blinded: bigint, keypair: BlindKeyPair): bigint {
  if (blinded <= 0n || blinded >= keypair.n) {
    throw new Error('Blinded message is out of range for this modulus');
  }

  return modPow(blinded, keypair.d, keypair.n);
}

/**
 * Remove the blinding factor, yielding a signature over the raw serial.
 *
 * @param blindSignature The issuer's response.
 * @param blindingFactor The r used when blinding.
 * @param publicKey The issuer's public key.
 */
export function unblind(
  blindSignature: bigint,
  blindingFactor: bigint,
  publicKey: BlindPublicKey,
): bigint {
  const inverse = modInverse(blindingFactor, publicKey.n);
  return (blindSignature * inverse) % publicKey.n;
}

/**
 * Verify a voucher signature against its serial.
 *
 * @returns True if `signature^e ≡ FDH(serial) (mod n)`.
 */
export function verifyBlindSignature(
  serial: Uint8Array,
  signature: bigint,
  publicKey: BlindPublicKey,
): boolean {
  const { n, e } = publicKey;
  if (signature <= 0n || signature >= n) return false;

  return modPow(signature, e, n) === fullDomainHash(serial, n);
}

/** Uniform random value in [0, bound). */
function randomBigIntBelow(bound: bigint): bigint {
  const byteLength = (bound.toString(16).length + 1) >> 1;

  const bytes = new Uint8Array(byteLength);

  for (;;) {
    globalThis.crypto.getRandomValues(bytes);

    let value = 0n;
    for (const byte of bytes) {
      value = (value << 8n) | BigInt(byte);
    }

    if (value < bound) return value;
  }
}

function base64UrlToBigInt(value: string): bigint {
  // `atob` rather than `Buffer`: present in Node 16+, browsers and
  // React Native, whereas `Buffer` is Node-only.
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));

  let result = 0n;
  for (let i = 0; i < binary.length; i++) {
    const byte = binary.charCodeAt(i);
    result = (result << 8n) | BigInt(byte);
  }

  return result;
}
