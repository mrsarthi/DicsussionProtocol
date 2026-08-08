/**
 * @dicsussion/sdk — Deterministic Identity Derivation
 *
 * Derives every key an identity needs from a single BIP-39 seed, so a
 * user who loses their device can restore the *same* identity from a
 * twelve-word phrase rather than becoming a stranger to their own
 * contacts and channels.
 *
 * Each key is derived under its own HKDF label. Reusing one secret
 * across the signing key, the encryption key and the RLN secret would
 * mean compromising any one of them compromises all three.
 *
 * ⚠️ THE RSA BLIND-SIGNING KEY IS NOT DERIVED. Deterministic RSA
 * requires a seeded prime search that Node's `crypto` does not expose,
 * and hand-rolling one is a poor trade against the benefit. It is
 * regenerated on recovery, with these consequences:
 *
 *   - `did:key`, encryption key, RLN secret and trapdoor all recover, so
 *     `cm_identity` is unchanged and **channel membership survives**.
 *   - Vouchers previously *issued* by this node still verify, because a
 *     voucher token carries its issuer's public key.
 *   - Peers holding the old `endorsementPublicKey` must re-pair before
 *     they can request new endorsements.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { BN254_SCALAR_FIELD } from '@dicsussion/core/crypto';
import type { KeyPair } from '@dicsussion/core/crypto';
import { deriveTrapdoor, membershipCommitment } from '@dicsussion/core/crypto';
import { publicKeyToDidKey } from '@dicsussion/core/transport';
import type { Ed25519KeyPair } from '@dicsussion/core/transport';

/** Entropy bits for generated phrases — 128 gives twelve words. */
export const MNEMONIC_STRENGTH_BITS = 128;

/** HKDF labels. Changing any of these changes the derived identity. */
const LABEL = {
  signing: 'dicsussion/identity/signing/v1',
  encryption: 'dicsussion/identity/encryption/v1',
  rlnSecret: 'dicsussion/identity/rln-secret/v1',
} as const;

/** Everything derivable from a seed — all but the RSA blind key. */
export interface DerivedIdentity {
  readonly did: string;
  readonly signing: Ed25519KeyPair;
  readonly encryption: KeyPair;
  readonly identitySecret: bigint;
  readonly trapdoor: bigint;
  readonly commitment: bigint;
}

/** Generate a fresh BIP-39 recovery phrase. */
export function createMnemonic(): string {
  return generateMnemonic(wordlist, MNEMONIC_STRENGTH_BITS);
}

/** Whether a phrase is a well-formed BIP-39 mnemonic with a valid checksum. */
export function isValidMnemonic(mnemonic: string): boolean {
  try {
    return validateMnemonic(normalise(mnemonic), wordlist);
  } catch {
    return false;
  }
}

/**
 * Derive a complete identity from a recovery phrase.
 *
 * Deterministic: the same phrase always yields the same `did:key` and
 * the same `cm_identity`.
 *
 * @param mnemonic A BIP-39 phrase.
 * @throws If the phrase is not a valid mnemonic.
 */
export function deriveIdentity(mnemonic: string): DerivedIdentity {
  const phrase = normalise(mnemonic);

  if (!validateMnemonic(phrase, wordlist)) {
    throw new Error('Invalid recovery phrase: failed BIP-39 checksum validation');
  }

  const seed = mnemonicToSeedSync(phrase);

  try {
    const signingSecret = derive(seed, LABEL.signing, 32);
    const encryptionSecret = derive(seed, LABEL.encryption, 32);

    const signing: Ed25519KeyPair = {
      secretKey: signingSecret,
      publicKey: ed25519.getPublicKey(signingSecret),
    };
    const encryption: KeyPair = {
      secretKey: encryptionSecret,
      publicKey: x25519.getPublicKey(encryptionSecret),
    };

    const identitySecret = deriveFieldElement(seed, LABEL.rlnSecret);

    // Derived from the secret, not independently: a peer who recovers
    // `a_0` by slashing must be able to compute `cm_identity`, and could
    // never know independent randomness. See `deriveTrapdoor`.
    const trapdoor = deriveTrapdoor(identitySecret);

    return {
      did: publicKeyToDidKey(signing.publicKey),
      signing,
      encryption,
      identitySecret,
      trapdoor,
      commitment: membershipCommitment(identitySecret, trapdoor),
    };
  } finally {
    // The 64-byte BIP-39 seed regenerates *every* key here, so it is the
    // single most valuable secret in the process — and unlike the keys
    // themselves it has no further use once derivation is done.
    //
    // JavaScript offers no guaranteed erasure: the GC may already have
    // copied this buffer, and strings are immutable. Overwriting still
    // removes the longest-lived copy, which is the one a heap dump or a
    // swapped page is most likely to catch. Partial mitigation, worth
    // its two lines.
    seed.fill(0);
  }
}

/** HKDF-expand the seed under a label. */
function derive(seed: Uint8Array, label: string, length: number): Uint8Array {
  return hkdf(sha256, seed, undefined, new TextEncoder().encode(label), length);
}

/**
 * Derive a uniform non-zero BN254 scalar.
 *
 * Rejection sampling with a counter rather than `mod r`: reducing a
 * 256-bit sample would bias the low end of the field, and these values
 * feed directly into nullifier and commitment derivation.
 */
function deriveFieldElement(seed: Uint8Array, label: string): bigint {
  for (let counter = 0; counter < 256; counter++) {
    const bytes = derive(seed, `${label}/${counter}`, 32);

    let value = 0n;
    for (const byte of bytes) {
      value = (value << 8n) | BigInt(byte);
    }

    if (value > 0n && value < BN254_SCALAR_FIELD) return value;
  }

  // 256 consecutive rejections is cryptographically impossible; treating
  // it as an error beats silently biasing the result.
  throw new Error(`Failed to derive a canonical field element for ${label}`);
}

/** Normalise whitespace and case so cosmetic differences still recover. */
function normalise(mnemonic: string): string {
  return mnemonic.trim().toLowerCase().split(/\s+/).join(' ');
}
