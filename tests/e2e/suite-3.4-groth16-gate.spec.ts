/**
 * Phase 3 — Groth16 proofs on the message path.
 *
 * The RLN signal (suite 3.3) enforces the rate limit. It does *not*
 * establish that the sender belongs to the channel or meets a
 * reputation threshold — that is what the Groth16 proof is for, and
 * until now it was generated nowhere on the send path.
 *
 * The tests that matter most here are the binding tests. A proof that
 * verifies cryptographically but is not tied to *this* message and
 * *our* member set is decorative: it proves that someone, somewhere,
 * once satisfied the circuit.
 *
 * Proving is ~1s, so this suite is deliberately small.
 */

import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '@dicsussion/core/transport';
import { BoundedMembershipTree } from '@dicsussion/core/crdt';
import {
  deriveTrapdoor,
  membershipCommitment,
} from '@dicsussion/core/crypto';
import {
  createSignal,
  currentEpoch,
  resolveArtifacts,
  ZekPocProver,
} from '@dicsussion/core/zk';
import { StreamType } from '@dicsussion/core/transport';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { ProofService } from '../../packages/HLessEnd/src/proof-service.js';
import { verifyGenesisAnchor } from '../../packages/HLessEnd/src/wot/genesis-anchor.js';
import type { SdkChatMessage } from '../../packages/HLessEnd/src/types.js';
import { sha256 } from '@noble/hashes/sha2.js';

/** Skip when the 4.9 MB proving key is not present in this checkout. */
const artifacts = resolveArtifacts();

test.describe('Suite 3.4 — Groth16 on the Message Path', () => {
  test.skip(
    artifacts === null,
    'circuit artifacts absent; run `npm run zk:build`',
  );

  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('proofs are off by default, so no proof rides with a message', async () => {
    const client = await DicsussionClient.init({
      storagePath: ':memory:',
      allowDevelopmentCeremony: true,
    });

    try {
      const sent = await client.chat.sendMessage({
        channelId: 'anon',
        content: 'cheap path',
        anonymous: true,
      });

      // The RLN signal is still there — that is what enforces the rate
      // limit, and it is unconditional.
      expect(sent.nullifierHash).toBeDefined();
      expect(sent.zkProof).toBeUndefined();
    } finally {
      await client.disconnect();
    }
  });

  test('enabling proofs attaches one that verifies against the channel root', async () => {
    const client = await DicsussionClient.init({
      storagePath: ':memory:',
      zkProofs: 'anonymous',
      allowDevelopmentCeremony: true,
    });

    try {
      const group = await client.groups.createGroup('proven', []);

      const sent = await client.chat.sendMessage({
        channelId: group.groupId,
        content: 'proven send',
        anonymous: true,
      });

      expect(sent.zkProof).toBeDefined();

      const wire = JSON.parse(sent.zkProof!) as {
        publicSignals: string[];
      };
      // Eight signals: two circuit outputs then six public inputs.
      expect(wire.publicSignals).toHaveLength(8);

      // Signal 2 is the membership root, and it must be *our* root.
      const tree = client.groups.getMembershipTree(group.groupId)!;
      expect(BigInt(wire.publicSignals[2]!)).toBe(tree.rawRoot());
    } finally {
      await client.disconnect();
    }
  });

  test('a channel with no member set never demands a proof', async () => {
    const client = await DicsussionClient.init({
      storagePath: ':memory:',
      zkProofs: 'anonymous',
      allowDevelopmentCeremony: true,
    });

    try {
      // Policy lives in the channel's signed anchor. An ad-hoc channel
      // has none, so there is no member set to prove against and none
      // is demanded — the local preference does not get to invent a
      // requirement that peers cannot know about.
      const sent = await client.chat.sendMessage({
        channelId: 'ad-hoc',
        content: 'no anchor, no policy',
        anonymous: true,
      });

      expect(sent.nullifierHash).toBeDefined();
      expect(sent.zkProof).toBeUndefined();
    } finally {
      await client.disconnect();
    }
  });

  test('peers with opposite local settings still exchange messages', async () => {
    // Before policy moved into the anchor, this partitioned silently:
    // the strict peer dropped every message the lax peer sent, with no
    // error surfaced on either side. Both configurations are valid, so
    // nothing looked wrong — messages simply vanished.
    const lax = await DicsussionClient.init({
      storagePath: ':memory:',
      allowDevelopmentCeremony: true,
    });
    const strict = await DicsussionClient.init({
      storagePath: ':memory:',
      zkProofs: 'anonymous',
      allowDevelopmentCeremony: true,
    });

    try {
      lax.addPeer(strict.did, strict.encryptionPublicKey);
      strict.addPeer(lax.did, lax.encryptionPublicKey);
  for (const channel of ['ad-hoc', 'anon']) {
    lax.chat.createChannel(channel, [strict.did]);
  }
  for (const channel of ['ad-hoc', 'anon']) {
    strict.chat.createChannel(channel, [lax.did]);
  }
      await lax.connect(strict.getTicket());

      // Created by the lax peer, so the anchor says proofs are not
      // required — and the strict peer honours the channel, not its own
      // preference.
      const group = await lax.groups.createGroup('mixed', [strict.did]);
      const info = await lax.groups.getGroupInfo(group.groupId);
      await strict.groups.importGroup(
        info,
        lax.getGenesisAnchor(group.groupId)!,
      );

      expect(strict.groups.requiresProofs(group.groupId)).toBe(false);

      const received: SdkChatMessage[] = [];
      strict.chat.onMessage(group.groupId, (m) => received.push(m));

      await lax.chat.sendMessage({
        channelId: group.groupId,
        content: 'crosses the config divide',
        anonymous: true,
      });

      const deadline = Date.now() + 15_000;
      while (received.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 20));
      }

      expect(received).toHaveLength(1);
    } finally {
      await lax.disconnect();
      await strict.disconnect();
      clearTransportRegistry();
    }
  });

  test('a proof-required channel binds a member who would rather not pay', async () => {
    // The mirror case: the channel demands proofs, and a peer whose own
    // default is 'off' must still produce them. Policy is signed into
    // the anchor precisely so it cannot be renegotiated per peer.
    const creator = await DicsussionClient.init({
      storagePath: ':memory:',
      zkProofs: 'anonymous',
      allowDevelopmentCeremony: true,
    });

    try {
      const group = await creator.groups.createGroup('strict', [], {
        requireProofs: true,
      });

      expect(creator.getGenesisAnchor(group.groupId)!.requireProofs).toBe(true);
      expect(creator.groups.requiresProofs(group.groupId)).toBe(true);

      const sent = await creator.chat.sendMessage({
        channelId: group.groupId,
        content: 'paid for',
        anonymous: true,
      });

      expect(sent.zkProof).toBeDefined();
    } finally {
      await creator.disconnect();
    }
  });

  test('a joining member converges and its proofs are accepted', async () => {
    // Joining inserts your commitment into *your* tree. Existing members
    // learn nothing from that, so without an advertisement their root
    // never includes you — and on a proof-required channel every proof
    // you produce is checked against a root you are absent from and
    // silently rejected. Proof channels would work only for the creator.
    const creator = await DicsussionClient.init({
      storagePath: ':memory:',
      zkProofs: 'anonymous',
      allowDevelopmentCeremony: true,
    });
    const joiner = await DicsussionClient.init({
      storagePath: ':memory:',
      allowDevelopmentCeremony: true,
    });

    try {
      joiner.addPeer(creator.did, creator.encryptionPublicKey);
      creator.addPeer(joiner.did, joiner.encryptionPublicKey);
  for (const channel of ['ad-hoc', 'anon']) {
    joiner.chat.createChannel(channel, [creator.did]);
  }
  for (const channel of ['ad-hoc', 'anon']) {
    creator.chat.createChannel(channel, [joiner.did]);
  }
      await joiner.connect(creator.getTicket());

      const group = await creator.groups.createGroup('open', [], {
        requireProofs: true,
      });
      await joiner.groups.importGroup(
        await creator.groups.getGroupInfo(group.groupId),
        creator.getGenesisAnchor(group.groupId)!,
      );
      await joiner.groups.joinGroup(group.groupId);

      const converged = async () => {
        const deadline = Date.now() + 15_000;
        while (Date.now() < deadline) {
          const a = joiner.groups.getMembershipTree(group.groupId)?.rawRoot();
          const b = creator.groups.getMembershipTree(group.groupId)?.rawRoot();
          if (a !== undefined && a === b) return true;
          await new Promise((r) => setTimeout(r, 20));
        }
        return false;
      };

      expect(await converged()).toBe(true);

      const received: SdkChatMessage[] = [];
      creator.chat.onMessage(group.groupId, (m) => received.push(m));

      const sent = await joiner.chat.sendMessage({
        channelId: group.groupId,
        content: 'proven as a new member',
        anonymous: true,
      });
      expect(sent.zkProof).toBeDefined();

      const deadline = Date.now() + 15_000;
      while (received.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 20));
      }
      expect(received).toHaveLength(1);
    } finally {
      await creator.disconnect();
      await joiner.disconnect();
      clearTransportRegistry();
    }
  });

  test('an unceremonied proving key is refused unless explicitly allowed', async () => {
    // The marker file beside the zkey says this key came from a
    // single-party local ceremony. Such a key provides no security: its
    // creator can forge membership, tier, and unlimited quota, and every
    // forgery verifies. Until now that was a warning in a markdown file
    // that no code consulted.
    const secret = 8n;
    const tree = new BoundedMembershipTree();
    tree.insert(membershipCommitment(secret, deriveTrapdoor(secret)));

    // Since 2026-08-11 the bundled artifacts are the real ceremony output,
    // so pointing at them no longer triggers the guard. The guard is still
    // worth testing — it is what stops a development key reaching users —
    // so we synthesise the condition instead of deleting the test.
    //
    // Detection is `existsSync(dirname(zkeyPath) + '/DEVELOPMENT_ONLY.md')`,
    // so a temp directory holding only the marker is enough: the check
    // fires before any artifact is read.
    const devDir = mkdtempSync(join(tmpdir(), 'dicsussion-devkey-'));
    writeFileSync(
      join(devDir, 'DEVELOPMENT_ONLY.md'),
      '# Development ceremony\n\nSynthesised by the test suite.\n',
    );

    const unguarded = new ProofService({
      artifacts: {
        ...artifacts!,
        zkeyPath: join(devDir, 'rln_final.zkey'),
      },
      getIdentitySecret: () => secret,
      getMembershipTree: () => tree,
      // allowDevelopmentCeremony deliberately omitted
    });

    const signal = createSignal(
      secret,
      {
        version: 1,
        streamId: StreamType.E2EE_MESSAGE,
        epoch: currentEpoch(),
        tier: 0,
        ciphertextHash: sha256(new TextEncoder().encode('dev:0')),
        recipientId: 0n,
      },
      0,
    );

    await expect(unguarded.prove('channel', signal)).rejects.toThrow(
      /development ceremony/,
    );

    // Verifying is refused too — a node that trusts an unceremonied key
    // is accepting forgeries just as surely as one that produces them.
    await expect(
      unguarded.verify(
        'channel',
        { proof: {}, publicSignals: ['0', '0', '0', '0', '0', '0', '0', '0'] },
        { nullifier: 0n, x: 0n, y: 0n },
      ),
    ).rejects.toThrow(/development ceremony/);
  });

  test('the anchor signature covers the proof policy', async () => {
    const client = await DicsussionClient.init({
      storagePath: ':memory:',
      allowDevelopmentCeremony: true,
    });

    try {
      const group = await client.groups.createGroup('signed-policy', [], {
        requireProofs: true,
      });
      const anchor = client.getGenesisAnchor(group.groupId)!;

      expect(verifyGenesisAnchor(anchor)).toBe(true);

      // Flipping the policy must break the signature, or a relaying peer
      // could downgrade a channel to unproven in transit.
      expect(verifyGenesisAnchor({ ...anchor, requireProofs: false })).toBe(
        false,
      );
    } finally {
      await client.disconnect();
    }
  });

  test('a peer verifies a proof against its own view of the member set', async () => {
    const alice = await DicsussionClient.init({
      storagePath: ':memory:',
      zkProofs: 'anonymous',
      allowDevelopmentCeremony: true,
    });
    const bob = await DicsussionClient.init({
      storagePath: ':memory:',
      zkProofs: 'anonymous',
      allowDevelopmentCeremony: true,
    });

    try {
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
  for (const channel of ['ad-hoc', 'anon']) {
    alice.chat.createChannel(channel, [bob.did]);
  }
  for (const channel of ['ad-hoc', 'anon']) {
    bob.chat.createChannel(channel, [alice.did]);
  }
      await alice.connect(bob.getTicket());

      const group = await alice.groups.createGroup('shared', [bob.did]);
      const info = await alice.groups.getGroupInfo(group.groupId);

      // Bob adopts the anchored member set without joining, so both
      // sides hold the same root.
      await bob.groups.importGroup(info, alice.getGenesisAnchor(group.groupId)!);
      expect(bob.groups.getMembershipTree(group.groupId)!.rawRoot()).toBe(
        alice.groups.getMembershipTree(group.groupId)!.rawRoot(),
      );

      const received: SdkChatMessage[] = [];
      bob.chat.onMessage(group.groupId, (m) => received.push(m));

      await alice.chat.sendMessage({
        channelId: group.groupId,
        content: 'proven over the wire',
        anonymous: true,
      });

      const deadline = Date.now() + 20_000;
      while (received.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 20));
      }

      expect(received).toHaveLength(1);
      expect(received[0]!.proofValid).toBe(true);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
      clearTransportRegistry();
    }
  });

  test('a proof-gated recipient rejects a message with the proof stripped', async () => {
    const bob = await DicsussionClient.init({
      storagePath: ':memory:',
      zkProofs: 'anonymous',
      allowDevelopmentCeremony: true,
    });

    try {
      const group = await bob.groups.createGroup('gated', []);

      // If an absent proof were treated as acceptable, a sender could
      // simply omit it and be indistinguishable from one who complied.
      await expect(
        bob.chat.ingestRemote({
          id: 'stripped',
          channelId: group.groupId,
          content: 'no proof attached',
          timestamp: Math.floor(Date.now() / 1000),
          messageIndex: 0,
          nullifierHash: `0x${'11'.repeat(32)}`,
          rlnShare: { x: `0x${'22'.repeat(32)}`, y: `0x${'33'.repeat(32)}` },
        }),
      ).rejects.toThrow(/RLN signal failed validation/);
    } finally {
      await bob.disconnect();
    }
  });

  test('a valid proof for a self-made tree is rejected', async () => {
    // The attack this stops: mint a membership tree containing only
    // yourself, prove membership in it honestly, and the proof verifies
    // — it just proves membership of a group of one. Only comparing the
    // root against our own member set catches it.
    const secret = 7777n;
    const trapdoor = deriveTrapdoor(secret);

    const attackerTree = new BoundedMembershipTree();
    attackerTree.insert(membershipCommitment(secret, trapdoor));

    const honestTree = new BoundedMembershipTree();
    honestTree.insert(membershipCommitment(1234n, deriveTrapdoor(1234n)));

    const signal = createSignal(
      secret,
      {
        version: 1,
        streamId: StreamType.E2EE_MESSAGE,
        epoch: currentEpoch(),
        tier: 0,
        ciphertextHash: sha256(new TextEncoder().encode('forged:0')),
        recipientId: 0n,
      },
      0,
    );

    const attacker = new ProofService({
      artifacts: artifacts!,
      allowDevelopmentCeremony: true,
      getIdentitySecret: () => secret,
      getMembershipTree: () => attackerTree,
    });
    const wire = await attacker.prove('channel', signal);

    // Verified against the attacker's own tree, this passes.
    expect(
      await attacker.verify('channel', wire, {
        nullifier: signal.nullifier,
        x: signal.x,
        y: signal.y,
      }),
    ).toBe(true);

    // Against the real member set, it does not.
    const honest = new ProofService({
      artifacts: artifacts!,
      allowDevelopmentCeremony: true,
      getIdentitySecret: () => 1234n,
      getMembershipTree: () => honestTree,
    });

    expect(
      await honest.verify('channel', wire, {
        nullifier: signal.nullifier,
        x: signal.x,
        y: signal.y,
      }),
    ).toBe(false);
  });

  test('a forged reputation tier is rejected, though it verifies cryptographically', async () => {
    // `userScore` is a private input the prover chooses, and nothing
    // binds it to the identity, the tree, or any attestation. The
    // circuit only checks `userScore >= tierThreshold` — both sides
    // supplied by the same party. So a peer with a real score of 0 can
    // produce a *valid* proof claiming the top tier.
    //
    // That matters beyond bragging rights: quota follows from tier, so
    // an accepted tier-200 claim buys a 100x rate-limit allowance.
    const secret = 31337n;
    const trapdoor = deriveTrapdoor(secret);
    const tree = new BoundedMembershipTree();
    tree.insert(membershipCommitment(secret, trapdoor));

    const signal = createSignal(
      secret,
      {
        version: 1,
        streamId: StreamType.E2EE_MESSAGE,
        epoch: currentEpoch(),
        tier: 0,
        ciphertextHash: sha256(new TextEncoder().encode('liar:0')),
        recipientId: 0n,
      },
      0,
    );

    const prover = new ZekPocProver(artifacts!);
    const forged = await prover.generateProof({
      identitySecret: secret,
      trapdoor,
      userScore: 999_999, // a lie — private and unbound
      merkleProof: tree.proveMembership(membershipCommitment(secret, trapdoor)),
      merkleRoot: tree.rawRoot(),
      tierThreshold: 200, // top tier claimed publicly
      epoch: signal.epoch,
      messageIndex: signal.messageIndex,
      messageCommitment: signal.x,
      quota: 100, // the allowance the lie would buy
    });

    // The proof itself is cryptographically sound. This is the point:
    // Groth16 verification cannot catch this, so the caller must.
    expect(await prover.verifyProof(forged.proof, forged.publicSignals)).toBe(
      true,
    );

    const service = new ProofService({
      artifacts: artifacts!,
      allowDevelopmentCeremony: true,
      getIdentitySecret: () => secret,
      getMembershipTree: () => tree,
    });

    expect(
      await service.verify(
        'channel',
        { proof: forged.proof, publicSignals: forged.publicSignals },
        { nullifier: forged.nullifier, x: signal.x, y: forged.share },
      ),
    ).toBe(false);
  });

  test('this node refuses to claim a tier it cannot back', async () => {
    const secret = 99n;
    const tree = new BoundedMembershipTree();
    tree.insert(membershipCommitment(secret, deriveTrapdoor(secret)));

    const service = new ProofService({
      artifacts: artifacts!,
      allowDevelopmentCeremony: true,
      getIdentitySecret: () => secret,
      getMembershipTree: () => tree,
      getTier: () => 100,
    });

    const signal = createSignal(
      secret,
      {
        version: 1,
        streamId: StreamType.E2EE_MESSAGE,
        epoch: currentEpoch(),
        tier: 0,
        ciphertextHash: sha256(new TextEncoder().encode('tier:0')),
        recipientId: 0n,
      },
      0,
    );

    await expect(service.prove('channel', signal)).rejects.toThrow(
      /does not bind userScore/,
    );
  });

  test('a proof cannot be lifted from one message onto another', async () => {
    // Without binding the public signals to the message, a valid proof
    // becomes a reusable token: capture one, staple it to any message
    // you like, and every recipient accepts it.
    const secret = 4242n;
    const tree = new BoundedMembershipTree();
    tree.insert(membershipCommitment(secret, deriveTrapdoor(secret)));

    const service = new ProofService({
      artifacts: artifacts!,
      allowDevelopmentCeremony: true,
      getIdentitySecret: () => secret,
      getMembershipTree: () => tree,
    });

    const epoch = currentEpoch();
    const context = (index: number) => ({
      version: 1 as const,
      streamId: StreamType.E2EE_MESSAGE,
      epoch,
      tier: 0,
      ciphertextHash: sha256(new TextEncoder().encode(`msg:${index}`)),
      recipientId: 0n,
    });

    const first = createSignal(secret, context(0), 0);
    const second = createSignal(secret, context(1), 1);

    const wire = await service.prove('channel', first);

    expect(
      await service.verify('channel', wire, {
        nullifier: first.nullifier,
        x: first.x,
        y: first.y,
      }),
    ).toBe(true);

    // The same proof presented for a different message.
    expect(
      await service.verify('channel', wire, {
        nullifier: second.nullifier,
        x: second.x,
        y: second.y,
      }),
    ).toBe(false);
  });
});
