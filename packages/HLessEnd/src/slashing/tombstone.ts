/**
 * @dicsussion/slashing — Revocation Tombstones (RFC 003 §7)
 *
 * A tombstone announces that an identity has been neutralised. Because
 * it is gossiped on the high-priority stream `0x03` and permanently
 * blacklists its target, it must be impossible to forge — otherwise
 * anyone could silence anyone.
 *
 * Tombstones therefore carry their own evidence. A `SLASHED_DOUBLE_SHARE`
 * tombstone includes two shares published under one nullifier at
 * different message commitments; any receiver re-derives `a_0` from them
 * and checks it against the claimed identity. The validator's signature
 * says who observed it, but the *proof* is what makes it true — a
 * tombstone with a perfect signature and bad shares is still rejected.
 *
 * WHY THE TRAPDOOR IS REVEALED: `cm_identity = Poseidon(DS_member, a_0,
 * trapdoor)`, so a receiver cannot bind the recovered secret to the
 * commitment without the trapdoor. Publishing it is not a new disclosure
 * — the holder already surrendered `a_0` by double-sending, and the
 * trapdoor alone unlocks nothing else. Withholding it would make
 * tombstones unverifiable, which is far worse.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

import { fieldToBytes } from '@dicsussion/core/crypto';
import { membershipCommitment } from '@dicsussion/core/crypto';
import type { Ed25519KeyPair } from '@dicsussion/core/transport';
import { didKeyToPublicKey } from '@dicsussion/core/transport';
import type { PolynomialShare } from '@dicsussion/core/zk';
import { recoverSecret, verifyRecovery } from '@dicsussion/core/zk';

/** Why an identity was revoked (RFC 003 §7.1). */
export const RevocationReason = {
  /** Holder exceeded quota, surrendering their secret. */
  SLASHED_DOUBLE_SHARE: 'SLASHED_DOUBLE_SHARE',
  /** Holder voluntarily retired the identity. */
  USER_REVOKED: 'USER_REVOKED',
} as const;

export type RevocationReasonValue =
  (typeof RevocationReason)[keyof typeof RevocationReason];

/** The two conflicting shares that prove a quota violation. */
export interface DoubleSpendProof {
  readonly nullifier: bigint;
  readonly shareOne: { readonly x: bigint; readonly y: bigint };
  readonly shareTwo: { readonly x: bigint; readonly y: bigint };
}

/** A signed revocation announcement. */
export interface RevocationTombstone {
  readonly revocationId: string;
  /** `cm_identity` being revoked — not a did:key (RFC 003 §7.1). */
  readonly membershipCommitment: bigint;
  readonly reason: RevocationReasonValue;
  /** Present for SLASHED_DOUBLE_SHARE. */
  readonly doubleSpendProof?: DoubleSpendProof;
  /** The recovered `a_0`. */
  readonly reconstructedSecret?: bigint;
  /** Revealed so `cm_identity` can be recomputed by anyone. */
  readonly trapdoor?: bigint;
  /** Unix seconds. */
  readonly timestamp: number;
  /** did:key of the node that observed the violation. */
  readonly validatorDid: string;
  readonly signature: Uint8Array;
}

/** Why a tombstone was rejected. */
export type TombstoneRejection =
  | 'bad-signature'
  | 'unprovable-ownership'
  | 'missing-proof'
  | 'nullifier-mismatch'
  | 'duplicate-commitment'
  | 'secret-mismatch'
  | 'commitment-mismatch';

export type TombstoneVerdict =
  | { readonly valid: true }
  | { readonly valid: false; readonly reason: TombstoneRejection };

const encoder = new TextEncoder();

/**
 * Canonical bytes covered by the validator's signature.
 *
 * Length-prefixed so no two distinct tombstones can serialise alike.
 */
export function encodeTombstoneForSigning(
  tombstone: Omit<RevocationTombstone, 'signature'>,
): Uint8Array {
  const parts: Uint8Array[] = [
    encoder.encode('dicsussion/revocation-tombstone/v1'),
    lengthPrefixed(encoder.encode(tombstone.revocationId)),
    fieldToBytes(tombstone.membershipCommitment),
    lengthPrefixed(encoder.encode(tombstone.reason)),
    lengthPrefixed(encoder.encode(tombstone.validatorDid)),
    encodeUint64(tombstone.timestamp),
  ];

  if (tombstone.doubleSpendProof) {
    const proof = tombstone.doubleSpendProof;
    parts.push(
      fieldToBytes(proof.nullifier),
      fieldToBytes(proof.shareOne.x),
      fieldToBytes(proof.shareOne.y),
      fieldToBytes(proof.shareTwo.x),
      fieldToBytes(proof.shareTwo.y),
    );
  }
  if (tombstone.reconstructedSecret !== undefined) {
    parts.push(fieldToBytes(tombstone.reconstructedSecret));
  }
  if (tombstone.trapdoor !== undefined) {
    parts.push(fieldToBytes(tombstone.trapdoor));
  }

  return concat(parts);
}

/**
 * Build a signed tombstone from two conflicting shares.
 *
 * @param shares The two shares proving the violation.
 * @param trapdoor The offender's trapdoor, needed to bind the commitment.
 * @param validator The observing node's signing keypair and did:key.
 * @throws If the shares do not actually prove a double-spend.
 */
export function createSlashingTombstone(
  shares: readonly [PolynomialShare, PolynomialShare],
  trapdoor: bigint,
  validator: { keypair: Ed25519KeyPair; did: string },
  now: number = Math.floor(Date.now() / 1000),
): RevocationTombstone {
  const recovery = recoverSecret(shares[0], shares[1]);
  if (!recovery.recovered) {
    throw new Error(
      `Cannot build a slashing tombstone: shares do not prove a double-spend (${recovery.reason})`,
    );
  }

  const unsigned: Omit<RevocationTombstone, 'signature'> = {
    revocationId: `rev-${crypto.randomUUID()}`,
    membershipCommitment: membershipCommitment(recovery.identitySecret, trapdoor),
    reason: RevocationReason.SLASHED_DOUBLE_SHARE,
    doubleSpendProof: {
      nullifier: shares[0].nullifier,
      shareOne: { x: shares[0].x, y: shares[0].y },
      shareTwo: { x: shares[1].x, y: shares[1].y },
    },
    reconstructedSecret: recovery.identitySecret,
    trapdoor,
    timestamp: now,
    validatorDid: validator.did,
  };

  return {
    ...unsigned,
    signature: ed25519.sign(
      encodeTombstoneForSigning(unsigned),
      validator.keypair.secretKey,
    ),
  };
}

/**
 * Build a voluntary revocation tombstone (`USER_REVOKED`).
 *
 * Unlike a slashing tombstone this carries no double-spend evidence —
 * there is no misconduct to prove.
 *
 * **This tombstone is not verifiable by anyone else.** Its signature
 * proves only that the signer produced these bytes, not that they own
 * the commitment named inside, so `verifyTombstone` rejects it and peers
 * will not honour it over the wire. It is useful only for applying a
 * retirement locally; to make peers stop counting you as a member,
 * announce a channel departure, which *is* bound to your did:key.
 *
 * @param commitment The `cm_identity` being retired.
 * @param holder The identity's own keypair and did:key.
 */
export function createUserRevocation(
  commitment: bigint,
  holder: { keypair: Ed25519KeyPair; did: string },
  now: number = Math.floor(Date.now() / 1000),
): RevocationTombstone {
  const unsigned: Omit<RevocationTombstone, 'signature'> = {
    revocationId: `rev-${crypto.randomUUID()}`,
    membershipCommitment: commitment,
    reason: RevocationReason.USER_REVOKED,
    timestamp: now,
    validatorDid: holder.did,
  };

  return {
    ...unsigned,
    signature: ed25519.sign(
      encodeTombstoneForSigning(unsigned),
      holder.keypair.secretKey,
    ),
  };
}

/**
 * Verify a tombstone end to end.
 *
 * Checks the signature, then independently re-derives the secret from
 * the supplied shares and confirms it produces the claimed commitment.
 * A valid signature over fabricated shares is still rejected — that is
 * the difference between "someone said so" and "it is demonstrably true".
 */
export function verifyTombstone(tombstone: RevocationTombstone): TombstoneVerdict {
  const { signature, ...unsigned } = tombstone;

  try {
    const publicKey = didKeyToPublicKey(tombstone.validatorDid);
    if (!ed25519.verify(signature, encodeTombstoneForSigning(unsigned), publicKey)) {
      return { valid: false, reason: 'bad-signature' };
    }
  } catch {
    return { valid: false, reason: 'bad-signature' };
  }

  // A voluntary revocation carries no evidence binding the signer to the
  // commitment it names, so it can never be verified from the wire.
  //
  // The signature proves only that *someone* signed these bytes. It does
  // not prove they hold the identity secret behind `membershipCommitment`
  // — and commitments are public, gossiped in MEMBER_LIST frames so peers
  // can union their member sets. Accepting this would let anyone who has
  // seen a commitment permanently revoke it, with no recovery.
  //
  // A sound version needs proof of knowledge of `a_0`. Publishing `a_0`
  // itself would work but deanonymises every message the holder ever
  // sent, since RLN nullifiers derive from it — a poor trade for
  // retiring a key. Until that proof exists, voluntary revocation is a
  // local action only (see `SlashingCoordinator.applyLocalRevocation`).
  if (tombstone.reason === RevocationReason.USER_REVOKED) {
    return { valid: false, reason: 'unprovable-ownership' };
  }

  const proof = tombstone.doubleSpendProof;
  if (
    !proof ||
    tombstone.reconstructedSecret === undefined ||
    tombstone.trapdoor === undefined
  ) {
    return { valid: false, reason: 'missing-proof' };
  }

  const shareOne: PolynomialShare = { ...proof.shareOne, nullifier: proof.nullifier };
  const shareTwo: PolynomialShare = { ...proof.shareTwo, nullifier: proof.nullifier };

  // Same x means someone replayed one message twice, not that the holder
  // overspent. Accepting it would let anyone frame an honest peer.
  if (shareOne.x === shareTwo.x) {
    return { valid: false, reason: 'duplicate-commitment' };
  }

  const recovery = recoverSecret(shareOne, shareTwo);
  if (!recovery.recovered) {
    return {
      valid: false,
      reason:
        recovery.reason === 'nullifier-mismatch'
          ? 'nullifier-mismatch'
          : 'duplicate-commitment',
    };
  }

  if (
    recovery.identitySecret !== tombstone.reconstructedSecret ||
    !verifyRecovery(recovery.identitySecret, recovery.slope, [shareOne, shareTwo])
  ) {
    return { valid: false, reason: 'secret-mismatch' };
  }

  if (
    membershipCommitment(recovery.identitySecret, tombstone.trapdoor) !==
    tombstone.membershipCommitment
  ) {
    return { valid: false, reason: 'commitment-mismatch' };
  }

  return { valid: true };
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function encodeUint64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);

  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }

  return out;
}
