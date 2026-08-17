/**
 * @dicsussion/sdk — ChatService
 *
 * Message sending, receiving, and history access.
 * Per-channel listener cap of 64 per RFC 004 §7.4.
 *
 * The service is constructed bare and wired later via `attach()`, so it
 * can be exercised in isolation without standing up transport, storage,
 * and CRDT layers.
 */

import { v4 as uuidv4 } from 'uuid';

import { Emitter } from '@dicsussion/core/transport';
import type { DocumentManager } from '@dicsussion/core/crdt';
import type { MessagePayload } from './message-codec.js';
import type { OutboxManager } from './outbox.js';
import { currentEpoch } from './outbox.js';
import type { WireProof } from './proof-service.js';
import type { SdkChatMessage, SendMessageOptions } from './types.js';

/** Maximum listeners per channel (RFC 004 §7.4). */
const MAX_LISTENERS_PER_CHANNEL = 64;

type MessageCallback = (msg: SdkChatMessage) => void;

/** Collaborators the chat service needs once the engine is running. */
export interface ChatServiceDeps {
  /** Local CRDT document set — one document per channel. */
  readonly documents: DocumentManager;
  /** Offline queue used when the node has no live peers. */
  readonly outbox: OutboxManager;
  /** This node's did:key. */
  readonly getLocalDid: () => string;
  /** Whether the node currently considers itself online. */
  readonly isOnline: () => boolean;
  /** Encrypt and transmit a message to every connected peer. */
  readonly publish: (payload: MessagePayload) => Promise<void>;
  /** Persist a message to the local message stream. */
  readonly persist?: (message: SdkChatMessage) => Promise<void>;
  /**
   * Derive an RLN signal for an anonymous send (RFC 003 §4.1).
   *
   * Absent when no ZK engine is attached, in which case anonymous sends
   * are refused rather than silently falling back to attributed ones.
   */
  readonly createAnonymousSignal?: (
    channelId: string,
    messageIndex: number,
  ) => Promise<{
    nullifierHash: string;
    share: { x: string; y: string };
    /** Groth16 proof, present only when the channel requires one. */
    zkProof?: WireProof;
  }>;
  /**
   * Validate an inbound anonymous message's RLN signal.
   *
   * Returns false when the sender exceeded quota, the signal is
   * malformed, or an attached Groth16 proof fails to verify. Feeding
   * the share to the slashing detector happens here too, which is what
   * makes double-sends detectable on live traffic rather than only in
   * tests.
   */
  readonly verifyRlnSignal?: (payload: MessagePayload) => Promise<boolean>;
}

/**
 * Chat service managing message operations.
 */
export class ChatService {
  static readonly MAX_LISTENERS_PER_CHANNEL = MAX_LISTENERS_PER_CHANNEL;

  private readonly emitter = new Emitter<Record<string, [SdkChatMessage]>>();
  private readonly listenerCounts = new Map<string, number>();
  private deps: ChatServiceDeps | null = null;

  constructor() {
    // Cap enforcement is our own concern; Node's default warning at 10
    // would fire well before the RFC's limit of 64.
    this.emitter.setMaxListeners(MAX_LISTENERS_PER_CHANNEL + 1);
  }

  /** Wire the service to the running engine. */
  attach(deps: ChatServiceDeps): void {
    this.deps = deps;
  }

  /**
   * Send an E2EE message to a channel.
   *
   * The message is written to the channel's CRDT document immediately so
   * local state is correct whether or not the network is reachable. If
   * the node is offline the ciphertext is queued in the outbox and
   * flushed on reconnection (RFC 004 §7.4).
   */
  async sendMessage(options: SendMessageOptions): Promise<SdkChatMessage> {
    const deps = this.requireDeps();

    const id = uuidv4();
    const timestamp = Math.floor(Date.now() / 1000);
    // Sequence within this channel, so messages sharing a one-second
    // timestamp still order correctly (RFC 002 §4.3).
    const messageIndex = deps.documents.getMessageCount(options.channelId);

    // An anonymous message is identified by its nullifier instead of a
    // did:key. The two are mutually exclusive — carrying both would
    // defeat the anonymity the nullifier exists to provide.
    let authorDid: string | undefined = deps.getLocalDid();
    let nullifierHash: string | undefined;
    let rlnShare: { x: string; y: string } | undefined;
    let zkProof: WireProof | undefined;

    if (options.anonymous) {
      if (!deps.createAnonymousSignal) {
        throw new Error(
          'Anonymous sending requires the RLN engine; no signal source is attached',
        );
      }

      authorDid = undefined;
      ({
        nullifierHash,
        share: rlnShare,
        zkProof,
      } = await deps.createAnonymousSignal(options.channelId, messageIndex));
    }

    const payload: MessagePayload = {
      id,
      channelId: options.channelId,
      authorDid,
      content: options.content,
      timestamp,
      messageIndex,
      nullifierHash,
      rlnShare,
      zkProof,
    };

    // Local-first: record it before attempting any network work.
    this.recordLocally(deps, payload);

    const message: SdkChatMessage = {
      id,
      channelId: options.channelId,
      authorDid,
      nullifierHash,
      content: options.content,
      timestamp,
      verifiedTier: 0,
      proofEpoch: currentEpoch(),
      proofValid: true,
      envelopeRef: id,
      zkProof: zkProof ? JSON.stringify(zkProof) : undefined,
    };

    await deps.persist?.(message);

    // Try, then queue on failure — rather than deciding in advance
    // whether the peer is reachable.
    //
    // `isOnline()` is a prediction, and predictions about a network are
    // wrong. A transport can hold a connection it believes is live for as
    // long as it takes to notice otherwise: QUIC needs a timeout, and a
    // bridged host may never report the loss at all. Publishing on the
    // strength of that prediction and letting the error escape puts the
    // message in local history, in no retry queue, and leaves the caller
    // to guess — which is how a send that shows as sent arrives nowhere.
    //
    // Replay is safe: the outbox preserves the message id, and a channel
    // document keys messages by id, so a peer that did receive it
    // converges on the same entry rather than showing it twice.
    let published = false;

    if (deps.isOnline()) {
      try {
        await deps.publish(payload);
        published = true;
      } catch {
        // Fall through to the outbox. The peer looked reachable and was
        // not, which is precisely what the queue is for.
      }
    }

    if (!published) {
      deps.outbox.enqueue({
        id,
        channelId: options.channelId,
        content: options.content,
        createdAt: Date.now(),
        status: 'pending',
        proofEpoch: message.proofEpoch,
        retryCount: 0,
      });
    }

    return message;
  }

  /**
   * Get message history for a channel, newest last.
   *
   * Reads from the channel's CRDT document, which is the merged
   * authority for channel state (RFC 002 §4.3).
   *
   * @param channelId The channel to read.
   * @param limit Optional cap, applied to the most recent messages.
   */
  async getHistory(channelId: string, limit?: number): Promise<SdkChatMessage[]> {
    const deps = this.deps;
    if (!deps) return [];

    const doc = deps.documents.getDocument(channelId);
    if (!doc) return [];

    // Total order: timestamp, then sender sequence, then id. Every
    // replica computes the same ordering from the same message set.
    const messages = Object.values(doc.messages ?? {})
      .slice()
      .sort(
        (a, b) =>
          a.timestamp - b.timestamp ||
          (a.messageIndex ?? 0) - (b.messageIndex ?? 0) ||
          (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
      )
      .map((m): SdkChatMessage => ({
        id: m.id,
        channelId,
        authorDid: m.authorDid,
        nullifierHash: m.nullifierHash,
        content: m.content,
        timestamp: m.timestamp,
        verifiedTier: 0,
        proofEpoch: Math.floor(m.timestamp / 10),
        proofValid: true,
        envelopeRef: m.zkEnvelopeRef ?? m.id,
      }));

    return limit !== undefined ? messages.slice(-limit) : messages;
  }

  /**
   * Register a callback for incoming messages on a channel.
   * Enforces MAX_LISTENERS_PER_CHANNEL per RFC 004 §7.4.
   *
   * @returns Unsubscribe function.
   */
  onMessage(channelId: string, callback: MessageCallback): () => void {
    const current = this.listenerCounts.get(channelId) ?? 0;
    if (current >= MAX_LISTENERS_PER_CHANNEL) {
      throw new Error(
        `Listener cap reached for channel ${channelId}: ${current} >= ${MAX_LISTENERS_PER_CHANNEL}`,
      );
    }

    this.listenerCounts.set(channelId, current + 1);
    const eventName = `message:${channelId}`;
    this.emitter.on(eventName, callback);

    return () => {
      this.emitter.off(eventName, callback);
      const count = this.listenerCounts.get(channelId) ?? 1;
      this.listenerCounts.set(channelId, Math.max(0, count - 1));
    };
  }

  /**
   * Remove all listeners for a channel.
   */
  removeAllListeners(channelId: string): void {
    const eventName = `message:${channelId}`;
    this.emitter.removeAllListeners(eventName);
    this.listenerCounts.set(channelId, 0);
  }

  /**
   * Ingest a message received from a peer.
   *
   * Writes it into the channel document, persists it, and notifies
   * channel listeners. Called by the client when a `0x02` frame decrypts
   * successfully.
   */
  async ingestRemote(payload: MessagePayload): Promise<SdkChatMessage> {
    const deps = this.requireDeps();

    // An anonymous message is only admissible if its RLN signal checks
    // out. Recording first and validating later would let an over-quota
    // sender's message land regardless of the verdict.
    const proofValid = deps.verifyRlnSignal
      ? await deps.verifyRlnSignal(payload)
      : payload.nullifierHash === undefined;

    if (payload.nullifierHash !== undefined && !proofValid) {
      throw new Error(
        `Rejected anonymous message ${payload.id}: RLN signal failed validation`,
      );
    }

    this.recordLocally(deps, payload);

    const message: SdkChatMessage = {
      id: payload.id,
      channelId: payload.channelId,
      authorDid: payload.authorDid,
      nullifierHash: payload.nullifierHash,
      content: payload.content,
      timestamp: payload.timestamp,
      verifiedTier: 0,
      proofEpoch: Math.floor(payload.timestamp / 10),
      proofValid,
      envelopeRef: payload.id,
      // Surfaced so an app can tell "verified against a proof" from
      // "no proof was required" — `proofValid` alone conflates them.
      zkProof: payload.zkProof ? JSON.stringify(payload.zkProof) : undefined,
    };

    await deps.persist?.(message);
    this._emitMessage(payload.channelId, message);

    return message;
  }

  /**
   * Emit an incoming message to channel listeners.
   * Called internally by the client when frames arrive.
   */
  _emitMessage(channelId: string, message: SdkChatMessage): void {
    const eventName = `message:${channelId}`;
    this.emitter.emit(eventName, message);
  }

  /** Write a payload into the channel's CRDT document. */
  private recordLocally(deps: ChatServiceDeps, payload: MessagePayload): void {
    const { documents } = deps;

    if (!documents.hasDocument(payload.channelId)) {
      documents.createDocument(payload.channelId, payload.channelId);
    }

    documents.addMessage(payload.channelId, {
      id: payload.id,
      authorDid: payload.authorDid,
      nullifierHash: payload.nullifierHash,
      content: payload.content,
      timestamp: payload.timestamp,
      messageIndex: payload.messageIndex,
      zkEnvelopeRef: payload.id,
    });
  }

  private requireDeps(): ChatServiceDeps {
    if (!this.deps) {
      throw new Error(
        'ChatService is not attached to a running client. Use DicsussionClient.init().',
      );
    }
    return this.deps;
  }
}
