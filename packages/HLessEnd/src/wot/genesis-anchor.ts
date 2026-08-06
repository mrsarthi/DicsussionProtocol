/**
 * @dicsussion/wot — Channel Creator Genesis Anchor
 *
 * Bootstraps a channel's membership set from nothing.
 *
 * A bounded membership tree needs a first member, but with no central
 * registry there is no authority to admit one. The channel creator
 * resolves this by signing a genesis anchor over `(channelId,
 * creatorCommitment, initialRoot, createdAt)` with their Ed25519
 * identity key. That signature is the channel's root of trust: a joining
 * peer verifies it, then treats the creator's commitment as the
 * legitimate first leaf.
 *
 * Because the anchor commits to `initialRoot`, a creator cannot later
 * present a different starting tree to different peers without producing
 * two conflicting signatures over the same channel id — which is
 * detectable evidence of equivocation.
 *
 * The anchor also carries the channel's **proof policy**. This belongs
 * here rather than in local configuration: if each peer decided
 * independently whether anonymous messages need a Groth16 proof, two
 * peers holding different-but-valid settings would silently partition —
 * the stricter one drops every message the laxer one sends, and neither
 * sees an error. Signing the policy into the anchor means every member
 * derives the same answer from the same bytes.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

import {
  BoundedMembershipTree,
  DEFAULT_MAX_MEMBERS,
} from '@dicsussion/core/crdt';
import { fieldToBytes } from '@dicsussion/core/crypto';
import type { Ed25519KeyPair } from '@dicsussion/core/transport';
import { didKeyToPublicKey } from '@dicsussion/core/transport';

/** A signed statement that a channel exists and who created it. */
export interface GenesisAnchor {
  readonly channelId: string;
  /** Creator's did:key. */
  readonly creatorDid: string;
  /** Creator's Poseidon identity commitment — the first leaf. */
  readonly creatorCommitment: bigint;
  /** Membership root immediately after admitting the creator. */
  readonly initialRoot: bigint;
  /** Unix timestamp in seconds. */
  readonly createdAt: number;
  /**
   * Whether anonymous messages on this channel must carry a Groth16
   * membership proof.
   *
   * Set once at creation and signed, so it cannot be renegotiated by a
   * peer who would rather not pay the ~1s proving cost.
   */
  readonly requireProofs: boolean;
  /** Ed25519 signature over the canonical anchor bytes. */
  readonly signature: Uint8Array;
}

const encoder = new TextEncoder();

/**
 * Canonical byte encoding signed by the creator.
 *
 * Length-prefixed so no two distinct anchors can serialise identically
 * (a channel id containing a delimiter must not be able to impersonate
 * a different field layout).
 */
export function encodeAnchorForSigning(
  anchor: Omit<GenesisAnchor, 'signature'>,
): Uint8Array {
  const channelBytes = encoder.encode(anchor.channelId);
  const didBytes = encoder.encode(anchor.creatorDid);

  const parts: Uint8Array[] = [
    // v2 adds requireProofs. The domain tag changes with the layout so a
    // v1 anchor cannot be reinterpreted as a v2 one with the policy
    // silently reading as false.
    encoder.encode('dicsussion/genesis-anchor/v2'),
    lengthPrefixed(channelBytes),
    lengthPrefixed(didBytes),
    fieldToBytes(anchor.creatorCommitment),
    fieldToBytes(anchor.initialRoot),
    encodeUint64(anchor.createdAt),
    Uint8Array.of(anchor.requireProofs ? 1 : 0),
  ];

  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const buffer = new Uint8Array(total);

  let offset = 0;
  for (const part of parts) {
    buffer.set(part, offset);
    offset += part.length;
  }

  return buffer;
}

/**
 * Create and sign a genesis anchor for a new channel.
 *
 * @param channelId The channel identifier.
 * @param creatorKeypair The creator's Ed25519 identity keypair.
 * @param creatorDid The creator's did:key.
 * @param creatorCommitment The creator's Poseidon identity commitment.
 * @param now Unix seconds.
 * @param requireProofs Whether anonymous messages need a Groth16 proof.
 */
export function createGenesisAnchor(
  channelId: string,
  creatorKeypair: Ed25519KeyPair,
  creatorDid: string,
  creatorCommitment: bigint,
  now: number = Math.floor(Date.now() / 1000),
  requireProofs = false,
): { anchor: GenesisAnchor; tree: BoundedMembershipTree } {
  const tree = new BoundedMembershipTree();
  tree.insert(creatorCommitment, now * 1000);

  const unsigned: Omit<GenesisAnchor, 'signature'> = {
    channelId,
    creatorDid,
    creatorCommitment,
    initialRoot: tree.root(),
    createdAt: now,
    requireProofs,
  };

  const signature = ed25519.sign(
    encodeAnchorForSigning(unsigned),
    creatorKeypair.secretKey,
  );

  return { anchor: { ...unsigned, signature }, tree };
}

/**
 * Verify a genesis anchor's signature against the creator's did:key.
 *
 * The public key is recovered from `creatorDid` rather than accepted as
 * a parameter, so a forged anchor cannot supply a key of its own choosing.
 *
 * @returns True if the signature is valid for the claimed creator.
 */
export function verifyGenesisAnchor(anchor: GenesisAnchor): boolean {
  try {
    const publicKey = didKeyToPublicKey(anchor.creatorDid);
    const message = encodeAnchorForSigning({
      channelId: anchor.channelId,
      creatorDid: anchor.creatorDid,
      creatorCommitment: anchor.creatorCommitment,
      initialRoot: anchor.initialRoot,
      createdAt: anchor.createdAt,
      requireProofs: anchor.requireProofs,
    });

    return ed25519.verify(anchor.signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Rebuild a channel's membership tree from a verified anchor.
 *
 * Confirms both that the anchor is authentic and that its `initialRoot`
 * really is the root of a tree containing exactly the creator — a valid
 * signature over a mismatched root is still rejected.
 *
 * `capacity` MUST match the value the anchor was created under: it is
 * bound into the versioned root, so a mismatch is indistinguishable from
 * a forged anchor.
 *
 * @throws If the anchor fails verification or its root is inconsistent.
 */
export function bootstrapFromAnchor(
  anchor: GenesisAnchor,
  capacity: number = DEFAULT_MAX_MEMBERS,
): BoundedMembershipTree {
  if (!verifyGenesisAnchor(anchor)) {
    throw new Error(
      `Genesis anchor for channel ${anchor.channelId} failed signature verification`,
    );
  }

  const tree = new BoundedMembershipTree(capacity);
  tree.insert(anchor.creatorCommitment, anchor.createdAt * 1000);

  if (tree.root() !== anchor.initialRoot) {
    throw new Error(
      `Genesis anchor initialRoot does not match the creator-only tree for channel ${anchor.channelId}`,
    );
  }

  return tree;
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function encodeUint64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setUint32(0, Math.floor(value / 0x100000000), false);
  view.setUint32(4, value >>> 0, false);
  return out;
}
