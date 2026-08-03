import { test, expect } from '@playwright/test';

test.describe('SDK — DicsussionClient', () => {
  test('DicsussionClient.init creates a client instance', async () => {
    const { DicsussionClient } = await import(
      '../../packages/HLessEnd/src/client.js'
    );

    const client = await DicsussionClient.init({ storagePath: ':memory:' });
    expect(client).toBeDefined();
    expect(client.chat).toBeDefined();
    expect(client.groups).toBeDefined();
    expect(client.trust).toBeDefined();
    expect(client.identity).toBeDefined();
    await client.disconnect();
  });

  test('client uses config defaults', async () => {
    const { DicsussionClient } = await import(
      '../../packages/HLessEnd/src/client.js'
    );

    const client = await DicsussionClient.init();
    const config = client.getConfig();

    expect(config.storagePath).toBe(':memory:');
    expect(config.logLevel).toBe('info');
    expect(config.proofBackend).toBe('wasm');
    expect(config.autoReconnect).toBe(true);
    expect(config.proofTimeoutMs).toBe(30_000);
    expect(config.maxOutboxSize).toBe(1000);

    await client.disconnect();
  });

  test('ChatService enforces listener cap of 64', async () => {
    const { ChatService } = await import(
      '../../packages/HLessEnd/src/chat-service.js'
    );

    const chat = new ChatService();

    // Register 64 listeners
    const unsubs: (() => void)[] = [];
    for (let i = 0; i < 64; i++) {
      unsubs.push(chat.onMessage('test-channel', () => {}));
    }

    // 65th should throw
    expect(() => chat.onMessage('test-channel', () => {})).toThrow(/cap reached/);

    // Unsubscribe one, then re-register should work
    unsubs[0]!();
    expect(() => chat.onMessage('test-channel', () => {})).not.toThrow();
  });

  test('OutboxManager enqueue/markSent/markFailed', async () => {
    const { OutboxManager } = await import(
      '../../packages/HLessEnd/src/outbox.js'
    );

    const outbox = new OutboxManager(5);
    expect(outbox.size).toBe(0);

    outbox.enqueue({
      id: 'out-1',
      channelId: 'ch-1',
      content: 'hello',
      createdAt: Date.now(),
      status: 'pending',
      retryCount: 0,
    });
    expect(outbox.size).toBe(1);

    const pending = outbox.getPending();
    expect(pending.length).toBe(1);

    outbox.markSent('out-1');
    expect(outbox.size).toBe(0);
  });

  test('OutboxManager enforces max size', async () => {
    const { OutboxManager } = await import(
      '../../packages/HLessEnd/src/outbox.js'
    );

    const outbox = new OutboxManager(2);

    outbox.enqueue({ id: '1', channelId: 'c', content: 'a', createdAt: 1, status: 'pending', retryCount: 0 });
    outbox.enqueue({ id: '2', channelId: 'c', content: 'b', createdAt: 2, status: 'pending', retryCount: 0 });

    expect(() =>
      outbox.enqueue({ id: '3', channelId: 'c', content: 'c', createdAt: 3, status: 'pending', retryCount: 0 }),
    ).toThrow(/full/);
  });

  test('TrustService returns default untrusted profile', async () => {
    const { TrustService } = await import(
      '../../packages/HLessEnd/src/trust-service.js'
    );
    const { TrustTier } = await import(
      '../../packages/HLessEnd/src/wot/types.js'
    );

    const trust = new TrustService();
    const profile = await trust.getProfile('did:key:z6Mktest...');

    expect(profile.subjectiveScore).toBe(0);
    expect(profile.tier).toBe(TrustTier.Untrusted);
    expect(profile.isBlacklisted).toBe(false);
  });

  test('WoT score calculator computes correctly', async () => {
    const { calculateScore, scoreTier, buildProfile } = await import(
      '../../packages/HLessEnd/src/wot/score-calculator.js'
    );
    const { TrustTier } = await import(
      '../../packages/HLessEnd/src/wot/types.js'
    );

    // S = 10×5 + 5×2 - 2×1 = 50+10-2 = 58
    expect(calculateScore(5, 2, 1)).toBe(58);
    expect(scoreTier(58)).toBe(TrustTier.Standard);

    // S = 10×10 + 5×10 - 2×0 = 150
    expect(calculateScore(10, 10, 0)).toBe(150);
    expect(scoreTier(150)).toBe(TrustTier.Established);

    // S = 10×20 + 5×5 - 2×2 = 221
    expect(calculateScore(20, 5, 2)).toBe(221);
    expect(scoreTier(221)).toBe(TrustTier.HighReputation);

    // Blacklisted profile
    const profile = buildProfile('did:key:z6Mk...', 100, 100, 0, true);
    expect(profile.subjectiveScore).toBe(-Infinity);
    expect(profile.tier).toBe(TrustTier.Untrusted);
  });
});
