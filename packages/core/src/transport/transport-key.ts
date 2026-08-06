/**
 * @dicsussion/transport — Transport Key Derivation
 *
 * Derives the Ed25519 key Iroh uses for its QUIC/TLS endpoint identity
 * from the node's `did:key` signing key.
 *
 * WHY NOT REUSE THE IDENTITY KEY DIRECTLY: Iroh's `EndpointId` is a
 * 32-byte Ed25519 public key — structurally identical to ours, so the
 * same key *could* serve both. It is deliberately not reused. The
 * identity key signs application artifacts that outlive any connection
 * (genesis anchors, revocation tombstones); the transport key signs TLS
 * handshake transcripts chosen in part by whoever we are talking to.
 * Letting one key do both is cross-protocol reuse, which has produced
 * real attacks elsewhere and costs nothing to avoid.
 *
 * The derivation is deterministic, so a node's transport identity is
 * stable across restarts without storing a second secret.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';

import type { Ed25519KeyPair } from './did-key.js';

/**
 * HKDF domain separation label.
 *
 * Changing this rotates every node's transport identity, which breaks
 * any cached peer address. Treat it as frozen.
 */
export const TRANSPORT_KEY_INFO = 'dicsussion/transport-key/v1';

/** An Ed25519 keypair scoped to the transport layer. */
export interface TransportKeyPair {
  /** 32-byte Ed25519 secret, handed to Iroh's `SecretKey.fromBytes`. */
  readonly secretKey: Uint8Array;
  /** 32-byte public key — the peer's Iroh `EndpointId`. */
  readonly publicKey: Uint8Array;
}

/**
 * Derive this node's transport keypair from its identity keypair.
 *
 * @param identity The node's Ed25519 `did:key` keypair.
 * @returns A deterministic, domain-separated transport keypair.
 */
export function deriveTransportKey(identity: Ed25519KeyPair): TransportKeyPair {
  // The seed is the identity secret; the salt binds the public half so
  // two identities cannot collide even if a secret were ever duplicated.
  const secretKey = hkdf(
    sha256,
    identity.secretKey.subarray(0, 32),
    identity.publicKey,
    new TextEncoder().encode(TRANSPORT_KEY_INFO),
    32,
  );

  return {
    secretKey,
    publicKey: ed25519.getPublicKey(secretKey),
  };
}

/**
 * Derive only the public half, for predicting a peer's `EndpointId`.
 *
 * Not currently possible from a peer's `did:key` alone — derivation
 * needs the *secret*. Peers therefore publish their transport public key
 * in their ticket rather than it being computable from their DID. This
 * function exists for the local node, which does hold its own secret.
 */
export function transportPublicKey(identity: Ed25519KeyPair): Uint8Array {
  return deriveTransportKey(identity).publicKey;
}
