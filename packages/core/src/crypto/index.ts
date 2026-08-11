/**
 * @dicsussion/crypto
 *
 * Public API surface for the crypto module.
 */
export { PROTOCOL_VERSION } from './types.js';

export type { EncryptedPayload, KeyPair, SecurityEnvelope } from './types.js';
// Runtime-neutral base64 — `Buffer` is Node-only and breaks in browsers
export {
  base64ToBytes,
  base64UrlToBytes,
  base64UrlToUtf8,
  bytesToBase64,
  bytesToBase64Url,
  utf8ToBase64Url,
} from './base64.js';
// Key generation
export {
  deriveSharedSecret,
  generateEd25519Keypair,
  generateX25519Keypair,
} from './keys.js';
// Encryption
export {
  decrypt,
  decryptFromPeer,
  encrypt,
  encryptForPeer,
} from './encryption.js';
// Signatures
export { sign, verify } from './signatures.js';
// Envelope
export { deserializeEnvelope, serializeEnvelope } from './envelope.js';
// BN254 scalar field (RFC 003 §3.3)
export {
  assertCanonicalField,
  BN254_SCALAR_FIELD,
  bytesToField,
  compareFieldBytes,
  FIELD_BYTES,
  fieldToBytes,
  fieldToHex,
  hexToField,
  isCanonicalField,
  NonCanonicalFieldError,
  reduceToField,
} from './field.js';
// Domain-separated Poseidon (RFC 003 §3.1)
export {
  deriveTrapdoor,
  DomainSeparator,
  issuanceNullifier,
  membershipCommitment,
  poseidonDomain,
  poseidonHash,
  poseidonPair,
  rlnNullifier,
  slopeWitness,
  voucherNullifier,
} from './poseidon.js';

export type { DomainSeparatorValue } from './poseidon.js';
// Chaumian RSA-FDH blind signatures (RFC 003 §5)
export {
  blind,
  blindSign,
  fullDomainHash,
  generateBlindKeyPair,
  generateSerial,
  modInverse,
  modPow,
  RSA_MODULUS_BITS,
  RSA_MODULUS_BYTES,
  toPublicKey,
  unblind,
  verifyBlindSignature,
} from './blind-signature.js';

export type {
  BlindedMessage,
  BlindKeyPair,
  BlindPublicKey,
} from './blind-signature.js';
