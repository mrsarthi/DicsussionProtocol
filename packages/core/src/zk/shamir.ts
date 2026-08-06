/**
 * @dicsussion/zk — RLN Slashing Polynomial (2-of-2 Shamir)
 *
 * Implements the rate-limiting mechanism from RFC 003 §4.1.
 *
 * Every message reveals one point on a secret line:
 *
 *     y = a_0 + a_1 · x   (mod r)
 *
 * where `a_0` is the sender's identity secret and `a_1` is a private
 * witness derived per (epoch, message_index). The x-coordinate is the
 * message commitment, so every distinct message yields a distinct point.
 *
 * The security property is geometric, not procedural:
 *
 *   - **One point** — infinitely many lines pass through it, so `a_0`
 *     stays hidden and the sender remains anonymous.
 *   - **Two points sharing a nullifier** — exactly one line fits, so
 *     anyone can interpolate it and read `a_0` off the y-intercept.
 *
 * Since the nullifier `η = Poseidon(DS_nullifier, a_0, epoch, index)` is
 * fixed by (epoch, index), reusing an index within an epoch — i.e.
 * exceeding quota — is precisely what produces two points on one line.
 * A spammer therefore hands out their own secret key. Nobody has to
 * decide to punish them; the maths does it.
 */

import {
  assertCanonicalField,
  fieldAdd,
  fieldDiv,
  fieldMul,
  fieldSub,
} from '../crypto/field.js';

/** One revealed point on a sender's slashing polynomial. */
export interface PolynomialShare {
  /** Message commitment, the x-coordinate. */
  readonly x: bigint;
  /** Evaluation `a_0 + a_1·x`, the y-coordinate. */
  readonly y: bigint;
  /** Rate-limiting nullifier η this share was published under. */
  readonly nullifier: bigint;
}

/** Outcome of attempting to recover a secret from two shares. */
export type RecoveryResult =
  | { readonly recovered: true; readonly identitySecret: bigint; readonly slope: bigint }
  | { readonly recovered: false; readonly reason: RecoveryFailure };

/** Why recovery could not proceed. */
export type RecoveryFailure =
  /** Shares came from different nullifiers, so they lie on different lines. */
  | 'nullifier-mismatch'
  /** Identical x-coordinates — the same message, not a double-send. */
  | 'duplicate-commitment';

/**
 * Evaluate the slashing polynomial at `x`.
 *
 * @param identitySecret The secret a_0 (the y-intercept).
 * @param slope The private witness a_1.
 * @param x The message commitment.
 * @returns The share value y.
 */
export function evaluateShare(
  identitySecret: bigint,
  slope: bigint,
  x: bigint,
): bigint {
  assertCanonicalField(identitySecret);
  assertCanonicalField(slope);
  assertCanonicalField(x);

  return fieldAdd(identitySecret, fieldMul(slope, x));
}

/**
 * Recover `a_0` from two shares published under the same nullifier.
 *
 * With a degree-1 polynomial, two points determine the line:
 *
 *     a_1 = (y₂ - y₁) / (x₂ - x₁)
 *     a_0 = y₁ - a_1·x₁
 *
 * This is the whole slashing primitive. It is deliberately something
 * *any* observer can compute — detection requires no privileged role.
 *
 * @param first A share observed under nullifier η.
 * @param second A second share under the same η.
 * @returns The recovered secret, or why recovery was not possible.
 */
export function recoverSecret(
  first: PolynomialShare,
  second: PolynomialShare,
): RecoveryResult {
  if (first.nullifier !== second.nullifier) {
    return { recovered: false, reason: 'nullifier-mismatch' };
  }

  // Equal x means the same message was seen twice — a duplicate delivery,
  // not a quota violation. Treating it as slashable would let anyone
  // frame an honest peer by replaying their message.
  if (first.x === second.x) {
    return { recovered: false, reason: 'duplicate-commitment' };
  }

  const slope = fieldDiv(
    fieldSub(second.y, first.y),
    fieldSub(second.x, first.x),
  );
  const identitySecret = fieldSub(first.y, fieldMul(slope, first.x));

  return { recovered: true, identitySecret, slope };
}

/**
 * Check that a recovered secret actually explains both shares.
 *
 * Recovery is algebraic and will produce *some* answer for any two
 * points. Verifying the result closes the loop before anything as
 * consequential as a revocation tombstone is published.
 */
export function verifyRecovery(
  identitySecret: bigint,
  slope: bigint,
  shares: readonly PolynomialShare[],
): boolean {
  return shares.every(
    (share) => evaluateShare(identitySecret, slope, share.x) === share.y,
  );
}

/**
 * Find the first pair of shares that reveals a secret.
 *
 * Shares are grouped by nullifier; any group holding two distinct
 * x-coordinates is a quota violation.
 *
 * @param shares Observed shares, in any order.
 * @returns The recovered secret and the two shares proving it, if any.
 */
export function findSlashablePair(shares: readonly PolynomialShare[]): {
  readonly identitySecret: bigint;
  readonly slope: bigint;
  readonly shares: readonly [PolynomialShare, PolynomialShare];
} | undefined {
  const byNullifier = new Map<bigint, PolynomialShare[]>();

  for (const share of shares) {
    const group = byNullifier.get(share.nullifier) ?? [];
    group.push(share);
    byNullifier.set(share.nullifier, group);
  }

  for (const group of byNullifier.values()) {
    if (group.length < 2) continue;

    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        const result = recoverSecret(group[i]!, group[j]!);
        if (!result.recovered) continue;

        if (
          verifyRecovery(result.identitySecret, result.slope, [
            group[i]!,
            group[j]!,
          ])
        ) {
          return {
            identitySecret: result.identitySecret,
            slope: result.slope,
            shares: [group[i]!, group[j]!],
          };
        }
      }
    }
  }

  return undefined;
}
