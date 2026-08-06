/**
 * @dicsussion/slashing — Coordinator Assembly
 *
 * Wires `SlashingCoordinator` to a client's identity, connections and
 * trust store, keeping the assembly out of the client facade.
 */

import { deriveTrapdoor, fieldToHex } from '@dicsussion/core/crypto';
import type { IConnection } from '@dicsussion/core/transport';
import type { Ed25519KeyPair } from '@dicsussion/core/transport';
import type { TrustStore } from '../wot/trust-store.js';
import { SlashingCoordinator } from './slashing-coordinator.js';

/** Identity material the coordinator needs. */
export interface SlashingIdentity {
  readonly did: string;
  readonly signing: Ed25519KeyPair;
  readonly identitySecret: bigint;
  readonly trapdoor: bigint;
}

export interface SlashingStackOptions {
  /** Resolves the live local identity, never a stale copy. */
  readonly getIdentity: () => SlashingIdentity;
  /** Live connections to gossip over. */
  readonly connections: () => IConnection[];
  /** Store whose blacklist a verified tombstone drives. */
  readonly store: TrustStore;
}

/**
 * Build a coordinator that gossips shares and applies tombstones.
 */
export function createSlashingStack(
  options: SlashingStackOptions,
): SlashingCoordinator {
  return new SlashingCoordinator({
    validator: () => {
      const identity = options.getIdentity();
      return { keypair: identity.signing, did: identity.did };
    },

    connections: options.connections,

    onRevoked: async (tombstone) => {
      // A revoked identity is blacklisted to −∞ (RFC 004 §6.1). The
      // tombstone targets `cm_identity` rather than a did:key, so the
      // commitment itself is the durable record.
      await options.store.blacklist(
        fieldToHex(tombstone.membershipCommitment),
        tombstone.timestamp,
      );
    },

    // The trapdoor is derived from the secret, so recovering `a_0` from
    // two shares is enough to compute *any* offender's `cm_identity`.
    // With independent randomness this was impossible, and slashing
    // could only ever fire against ourselves.
    resolveTrapdoor: (identitySecret) => deriveTrapdoor(identitySecret),
  });
}
