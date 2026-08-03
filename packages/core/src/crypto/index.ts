/**
 * @dicsussion/crypto
 *
 * Public API surface for the crypto module.
 */

// Types
export type { EncryptedPayload, KeyPair, SecurityEnvelope } from './types.js';
export { PROTOCOL_VERSION } from './types.js';

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
