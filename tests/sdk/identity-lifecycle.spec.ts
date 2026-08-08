/**
 * Identity lifecycle — the other half of RFC 004 §7.3.
 *
 * The property that matters for a consumer app: losing a device must not
 * mean losing your identity. Recovery has to reproduce the *same*
 * `did:key` and the same `cm_identity`, or channel membership and
 * reputation are silently lost.
 */

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '../../packages/core/src/transport/local-transport.js';
import { membershipCommitment } from '../../packages/core/src/crypto/poseidon.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import {
  createMnemonic,
  deriveIdentity,
  isValidMnemonic,
} from '../../packages/HLessEnd/src/identity-derivation.js';
import { IdentityService } from '../../packages/HLessEnd/src/identity-service.js';

test.describe('SDK — Mnemonic Derivation', () => {
  test('a generated phrase is twelve valid BIP-39 words', () => {
    const mnemonic = createMnemonic();

    expect(mnemonic.split(' ')).toHaveLength(12);
    expect(isValidMnemonic(mnemonic)).toBe(true);
  });

  test('derivation is deterministic across calls', () => {
    const mnemonic = createMnemonic();
    const first = deriveIdentity(mnemonic);
    const second = deriveIdentity(mnemonic);

    expect(second.did).toBe(first.did);
    expect(second.commitment).toBe(first.commitment);
    expect(Array.from(second.signing.secretKey)).toEqual(
      Array.from(first.signing.secretKey),
    );
    expect(Array.from(second.encryption.secretKey)).toEqual(
      Array.from(first.encryption.secretKey),
    );
  });

  test('different phrases yield different identities', () => {
    const a = deriveIdentity(createMnemonic());
    const b = deriveIdentity(createMnemonic());

    expect(a.did).not.toBe(b.did);
    expect(a.commitment).not.toBe(b.commitment);
  });

  test('each key is derived under its own label', () => {
    const derived = deriveIdentity(createMnemonic());

    // Reusing one secret across signing, encryption and RLN would mean
    // compromising any one compromises all three.
    const secrets = [
      Buffer.from(derived.signing.secretKey).toString('hex'),
      Buffer.from(derived.encryption.secretKey).toString('hex'),
      derived.identitySecret.toString(16),
      derived.trapdoor.toString(16),
    ];

    expect(new Set(secrets).size).toBe(4);
  });

  test('the commitment matches Poseidon over the derived secrets', () => {
    const derived = deriveIdentity(createMnemonic());

    expect(derived.commitment).toBe(
      membershipCommitment(derived.identitySecret, derived.trapdoor),
    );
  });

  test('cosmetic whitespace and case differences still recover', () => {
    const mnemonic = createMnemonic();
    const messy = `  ${mnemonic.toUpperCase().split(' ').join('   ')}  `;

    expect(deriveIdentity(messy).did).toBe(deriveIdentity(mnemonic).did);
  });

  test('an invalid phrase is rejected rather than silently derived', () => {
    expect(isValidMnemonic('not actually a mnemonic at all')).toBe(false);
    expect(() => deriveIdentity('not actually a mnemonic at all')).toThrow(
      /Invalid recovery phrase/,
    );

    // A phrase of real wordlist words but a broken checksum must also
    // fail. The final word carries 4 checksum bits, so ~1 in 16
    // substitutions is coincidentally valid — search for one that is
    // genuinely invalid rather than assuming the first attempt breaks it.
    const words = createMnemonic().split(' ');
    const broken = findInvalidVariant(words);

    expect(isValidMnemonic(broken)).toBe(false);
    expect(() => deriveIdentity(broken)).toThrow(/Invalid recovery phrase/);
  });
});

/**
 * Produce a phrase of valid words whose checksum does not hold.
 *
 * @throws If no invalid variant is found, which would mean the checksum
 *   is not being enforced at all.
 */
function findInvalidVariant(words: readonly string[]): string {
  for (const candidate of words) {
    const mutated = [...words];
    mutated[11] = candidate;

    const phrase = mutated.join(' ');
    if (!isValidMnemonic(phrase)) return phrase;
  }

  throw new Error('Every substitution produced a valid checksum');
}

test.describe('SDK — Identity Recovery', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('a fresh identity exports a usable recovery phrase', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const mnemonic = await client.identity.exportMnemonic();

      expect(isValidMnemonic(mnemonic)).toBe(true);
      expect(deriveIdentity(mnemonic).did).toBe(client.did);
    } finally {
      await client.disconnect();
    }
  });

  test('recovery on a new device restores the same identity', async () => {
    const original = await DicsussionClient.init({ storagePath: ':memory:' });
    const mnemonic = await original.identity.exportMnemonic();

    const originalDid = original.did;
    const originalCommitment = original.identityCommitment;
    const originalEncryptionKey = Array.from(original.encryptionPublicKey);
    await original.disconnect();

    // A different device with its own empty database.
    const restored = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      await restored.identity.recoverFromMnemonic(mnemonic);

      expect(restored.did).toBe(originalDid);
      // Same commitment means channel membership and reputation survive.
      expect(restored.identityCommitment).toBe(originalCommitment);
      expect(Array.from(restored.encryptionPublicKey)).toEqual(originalEncryptionKey);
    } finally {
      await restored.disconnect();
    }
  });

  test('recovery regenerates the blind-signing key, as documented', async () => {
    const original = await DicsussionClient.init({ storagePath: ':memory:' });
    const mnemonic = await original.identity.exportMnemonic();
    const originalBlindKey = (await original.getEndorsementKey()).n;
    await original.disconnect();

    const restored = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      await restored.identity.recoverFromMnemonic(mnemonic);

      // RSA is not derivable from the seed, so this key genuinely differs.
      // Peers holding the old one must re-pair before requesting
      // endorsements — see identity-derivation.ts.
      expect((await restored.getEndorsementKey()).n).not.toBe(originalBlindKey);
      // Everything seed-derived is unchanged.
      expect(restored.identityCommitment).toBe(
        deriveIdentity(mnemonic).commitment,
      );
    } finally {
      await restored.disconnect();
    }
  });

  test('an invalid phrase does not replace the loaded identity', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const before = client.did;

      await expect(
        client.identity.recoverFromMnemonic('clearly not a valid phrase'),
      ).rejects.toThrow(/Invalid recovery phrase/);

      expect(client.did).toBe(before);
    } finally {
      await client.disconnect();
    }
  });

  test('exportMnemonic refuses when no identity is loaded', async () => {
    const service = new IdentityService();

    await expect(service.exportMnemonic()).rejects.toThrow(/No identity loaded/);
  });
});

test.describe('SDK — Key Revocation', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('revokeKey retires this identity commitment', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const commitment = client.identityCommitment;
      expect(client.isRevoked(commitment)).toBe(false);

      await client.identity.revokeKey();

      // Applied locally even with no peers connected — a half-broadcast
      // revocation must not leave the holder still counting as active.
      expect(client.isRevoked(commitment)).toBe(true);
    } finally {
      await client.disconnect();
    }
  });

  test('a peer does NOT honour a voluntary revocation from the wire', async () => {
    // A USER_REVOKED tombstone proves only that *someone* signed those
    // bytes — never that they hold the identity secret behind the
    // commitment named inside. Commitments are public (MEMBER_LIST
    // gossips them), so honouring this would let anyone permanently
    // revoke anyone. Alice retires locally; Bob is unmoved.
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
      await alice.connect(bob.getTicket());

      const commitment = alice.identityCommitment;
      await alice.identity.revokeKey();

      expect(alice.isRevoked(commitment)).toBe(true);

      // Give any (incorrect) gossip time to arrive and be applied.
      await new Promise((r) => setTimeout(r, 300));
      expect(bob.isRevoked(commitment)).toBe(false);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('revocation fires a slashing event with no evidence', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const events: Array<{ reason: string; hasEvidence: boolean }> = [];
      client.onSlashing((event) =>
        events.push({
          reason: event.tombstone.reason,
          hasEvidence: event.evidence !== undefined,
        }),
      );

      await client.identity.revokeKey();

      expect(events).toEqual([
        { reason: 'USER_REVOKED', hasEvidence: false },
      ]);
    } finally {
      await client.disconnect();
    }
  });
});

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 3_000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return predicate();
}
