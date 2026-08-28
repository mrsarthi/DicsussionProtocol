/**
 * @dicsussion/sdk — ChatService
 *
 * Message sending, receiving, and history access.
 * Per-channel listener cap of 64 per RFC 004 §7.5.
 *
 * The service is constructed bare and wired later via `attach()`, so it
 * can be exercised in isolation without standing up transport, storage,
 * and CRDT layers.
 */

import { v4 as uuidv4 } from 'uuid';

import { Emitter } from '@dicsussion/core/transport';
import type { DocumentManager } from '@dicsussion/core/crdt';
import type { BlobRef } from './blob-service.js';
import type { MessagePayload } from './message-codec.js';
import type { OutboxManager } from './outbox.js';
import { currentEpoch } from './outbox.js';
import type { WireProof } from './proof-service.js';
import type { SdkChatMessage, SendMessageOptions } from './types.js';

/** Maximum listeners per channel (RFC 004 §7.5). */
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
  /**
   * Encrypt and transmit to every paired, connected peer.
   *
   * @returns How many peers it reached. Zero is a failure to deliver,
   *   not a success — see `sendMessage`.
   */
  readonly publish: (payload: MessagePayload) => Promise<number>;
  /** Persist a message to the local message stream. */
  readonly persist?: (message: SdkChatMessage) => Promise<void>;
  /**
   * A channel document changed locally.
   *
   * Fires for messages this node sent *and* messages it received, since
   * relaying what arrived is how a change reaches someone this node is
   * not directly connected to.
   */
  readonly onDocumentChanged?: (channelId: string) => void;
  /** Send an opaque payload to reachable participants; nothing stored. */
  readonly publishEphemeral?: (
    channelId: string,
    payload: Uint8Array,
  ) => Promise<number>;
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

  /** Message ids the application has already been told about. */
  private readonly emitted = new Map<string, Set<string>>();

  /**
   * Ids a channel already held when it was first observed.
   *
   * Deliberately distinct from `emitted`. History that was on disk at
   * startup must not be replayed as though it were arriving, but nor has
   * the application been told about it in this session — conflating the
   * two suppresses the very first message on a channel, because seeding
   * the baseline would mark it delivered before anything delivered it.
   */
  private readonly baseline = new Map<string, Set<string>>();

  /** Ephemeral listeners per channel; nothing here is persisted. */
  private readonly ephemeral = new Map<
    string,
    Set<(from: string, payload: Uint8Array) => void>
  >();
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
   * Create a conversation and record who belongs to it.
   *
   * The guest list decides who the conversation may be sent to and
   * synchronised with, so this is an authorization boundary rather than
   * bookkeeping. The local node is always included.
   *
   * Calling it is optional — `sendMessage` will create a channel on
   * first use — but doing so explicitly is clearer than relying on the
   * first message, and it is the only way to establish membership before
   * anything is sent.
   *
   * Idempotent: an existing channel gains any participants it lacks and
   * keeps everything it already had.
   *
   * @param channelId The conversation.
   * @param participants `did:key`s entitled to it, besides this node.
   */
  createChannel(channelId: string, participants: readonly string[] = []): void {
    const deps = this.requireDeps();

    if (!deps.documents.hasDocument(channelId)) {
      deps.documents.createDocument(channelId, channelId);
    }

    // **Authoritative, not additive.** Declaring a conversation states
    // who is in it, so anyone already recorded and not named here is
    // removed.
    //
    // The additive reading is unsafe. A channel can come into existence
    // from an inbound message, which records its sender — so if
    // declaring "this chat is for Bob" merely *added* Bob, a peer who
    // had already written itself in by naming the id would stay, and
    // receive the conversation. Use `addParticipant` to admit someone to
    // a conversation that already exists.
    const intended = new Set([deps.getLocalDid(), ...participants]);

    for (const existing of deps.documents.participants(channelId)) {
      if (!intended.has(existing)) {
        deps.documents.removeParticipant(channelId, existing);
      }
    }

    for (const did of intended) {
      deps.documents.addParticipant(channelId, did);
    }
  }

  /**
   * Admit someone to a conversation that already exists.
   *
   * `createChannel` states the whole membership; this adds to it. Use
   * this when someone joins a group rather than re-declaring the list,
   * which would remove everyone you did not repeat.
   *
   * @param channelId The conversation.
   * @param did Participant to admit.
   */
  addParticipant(channelId: string, did: string): void {
    this.requireDeps().documents.addParticipant(channelId, did);
  }

  /**
   * Remove someone from a conversation.
   *
   * They stop receiving new messages, stop being offered the document,
   * and their own pushes are refused. **What they already hold is
   * theirs** — removal is not retroactive, and an application should say
   * so rather than implying a chat can be un-shared.
   *
   * @param channelId The conversation.
   * @param did Participant to remove.
   * @returns Whether they were a participant.
   */
  removeParticipant(channelId: string, did: string): boolean {
    return this.requireDeps().documents.removeParticipant(channelId, did);
  }

  /**
   * Send an E2EE message to a channel.
   *
   * The message is written to the channel's CRDT document immediately so
   * local state is correct whether or not the network is reachable. If
   * the node is offline the ciphertext is queued in the outbox and
   * flushed on reconnection (RFC 004 §7.5).
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
      attachments: options.attachments,
      replyTo: options.replyTo,
      timestamp,
      messageIndex,
      nullifierHash,
      rlnShare,
      zkProof,
    };

    // Local-first: record it before attempting any network work.
    this.recordLocally(deps, payload, options.participants);

    // Our own message is returned to the caller, never delivered to them
    // as an arrival. Marking it emitted keeps the sync diff from treating
    // it as news later — otherwise a peer's first sync makes every
    // message this node sent appear to arrive from outside.
    this.markEmitted(options.channelId, id);

    const message: SdkChatMessage = {
      id,
      channelId: options.channelId,
      authorDid,
      nullifierHash,
      content: options.content,
      attachments: options.attachments,
      replyTo: options.replyTo,
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
        // Zero recipients is not delivery. An empty fan-out resolves
        // exactly like a successful one, so without this a node whose
        // only live connection is an unpaired stranger marks the message
        // sent and drops it.
        published = (await deps.publish(payload)) > 0;
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
   * Send a payload that is delivered but never stored.
   *
   * Presence, typing indicators and read receipts are the same shape:
   * true only while both peers are connected, and misleading afterwards.
   * Sending them as ordinary messages would work and would grow the
   * conversation forever — a heartbeat every thirty seconds is a few
   * thousand permanent entries per day, on every participant's device.
   *
   * So this deliberately has none of `sendMessage`'s guarantees. It is
   * not persisted, not queued, not retried, and not replayed to a peer
   * who reconnects. A recipient who is not connected right now does not
   * receive it, which is correct: a stale "typing…" is worse than none.
   *
   * The payload is opaque bytes. What a signal means is the
   * application's business — giving it a schema here would mean
   * revising the protocol whenever an application invents a new one.
   *
   * @param channelId Conversation the signal belongs to.
   * @param payload Opaque application bytes.
   * @returns How many peers received it. Zero is normal, not an error.
   */
  async sendEphemeral(channelId: string, payload: Uint8Array): Promise<number> {
    const deps = this.requireDeps();

    return (await deps.publishEphemeral?.(channelId, payload)) ?? 0;
  }

  /**
   * Listen for ephemeral payloads on a channel.
   *
   * @returns Unsubscribe function.
   */
  onEphemeral(
    channelId: string,
    handler: (from: string, payload: Uint8Array) => void,
  ): () => void {
    const listeners = this.ephemeral.get(channelId) ?? new Set();
    listeners.add(handler);
    this.ephemeral.set(channelId, listeners);

    return () => {
      listeners.delete(handler);
      if (listeners.size === 0) this.ephemeral.delete(channelId);
    };
  }

  /** Deliver an inbound ephemeral payload. Called by the client. */
  _emitEphemeral(from: string, channelId: string, payload: Uint8Array): void {
    for (const handler of this.ephemeral.get(channelId) ?? []) {
      handler(from, payload);
    }
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
        attachments: parseAttachments(m.attachments),
        replyTo: parseReplyTo(m.replyTo),
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
   * Enforces MAX_LISTENERS_PER_CHANNEL per RFC 004 §7.5.
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
      attachments: payload.attachments,
      replyTo: payload.replyTo,
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
   * Emit messages a CRDT sync just added to a channel.
   *
   * Messages reach a node two ways. An E2EE envelope on stream `0x02`
   * runs through `ingestRemote`, which emits. A message that arrives by
   * document sync on `0x01` is merged straight into the channel document
   * and, until this existed, notified nobody — so it appeared in
   * `getHistory()` and never in `onMessage`. To an application appending
   * on the event that is indistinguishable from the message being lost,
   * which is exactly how it was reported.
   *
   * De-duplication is by message id against what this channel has
   * already emitted. Both duplicate paths collapse into it: the same
   * message arriving over `0x02` and again by sync, and the same message
   * re-applied while syncing with a third peer. Channel documents key
   * messages by id (RFC 002 §3.1), so a re-apply is a no-op in the
   * document too.
   *
   * @param channelId Channel whose document advanced.
   * @returns The messages emitted by this call.
   */
  async emitSynced(channelId: string): Promise<SdkChatMessage[]> {
    const deps = this.deps;
    if (!deps) return [];

    // First sight of this channel records what it already held instead
    // of emitting it. Otherwise the first sync after a restart replays
    // the entire history as though it had just arrived.
    if (!this.baseline.has(channelId)) {
      this.baseline.set(
        channelId,
        new Set(Object.keys(deps.documents.getDocument(channelId)?.messages ?? {})),
      );
      return [];
    }

    const known = this.baseline.get(channelId)!;
    const told = this.emitted.get(channelId);

    const fresh = (await this.getHistory(channelId)).filter(
      (message) => !known.has(message.id) && !told?.has(message.id),
    );

    for (const message of fresh) this._emitMessage(channelId, message);
    return fresh;
  }

  /**
   * Tell the engine this channel advanced, once the write has landed.
   *
   * Deferred by a microtask so the document is already updated when the
   * push reads it, and so a failure to reach one peer cannot turn a
   * local write into a thrown error.
   */
  private scheduleSync(deps: ChatServiceDeps, channelId: string): void {
    if (!deps.onDocumentChanged) return;
    queueMicrotask(() => deps.onDocumentChanged?.(channelId));
  }

  /** Record an id as emitted, so sync does not emit it a second time. */
  private markEmitted(channelId: string, id: string): void {
    const seen = this.emitted.get(channelId);
    if (seen) seen.add(id);
    else this.emitted.set(channelId, new Set([id]));
  }

  /**
   * Emit an incoming message to channel listeners.
   * Called internally by the client when frames arrive.
   */
  _emitMessage(channelId: string, message: SdkChatMessage): void {
    // Once per message, whichever route delivered it first.
    //
    // A message can now arrive twice over: as an E2EE envelope on 0x02,
    // and again in a document sync relayed by a peer in the middle. Both
    // are legitimate and neither is redundant — the envelope is direct,
    // the relay is how it reaches someone the sender cannot see — but an
    // application must be told once, or a group chat shows every message
    // as many times as there are paths to it.
    if (this.emitted.get(channelId)?.has(message.id)) return;

    this.markEmitted(channelId, message.id);
    const eventName = `message:${channelId}`;
    this.emitter.emit(eventName, message);
  }

  /** Write a payload into the channel's CRDT document. */
  private recordLocally(
    deps: ChatServiceDeps,
    payload: MessagePayload,
    participants?: readonly string[],
  ): void {
    const { documents } = deps;

    if (!documents.hasDocument(payload.channelId)) {
      documents.createDocument(payload.channelId, payload.channelId);

      // Record the guest list at creation, because this is the only
      // moment it can be inferred. A channel comes into existence with
      // its first message and carries no membership of its own, so a
      // list not written here is never written — and the sync policy
      // refuses a conversation nobody is recorded in, which would leave
      // it stranded on one device.
      documents.addParticipant(payload.channelId, deps.getLocalDid());
      for (const did of participants ?? []) {
        documents.addParticipant(payload.channelId, did);
      }

      // A conversation someone else opened: record them, so a reply has
      // somewhere to go. This is the *only* place an author is inferred,
      // and only while the channel is being created in response to them.
      //
      // Inferring it on a channel that already exists is what made
      // channel ids security-relevant: a paired peer could name the id
      // of a conversation it was not part of, write itself into the
      // guest list, and receive everything sent there afterwards. An
      // explicit `createChannel` now overrides whatever was inferred, so
      // naming a conversation is what decides who is in it.
      if (payload.authorDid) {
        documents.addParticipant(payload.channelId, payload.authorDid);
      }
    }

    this.scheduleSync(deps, payload.channelId);

    documents.addMessage(payload.channelId, {
      id: payload.id,
      authorDid: payload.authorDid,
      nullifierHash: payload.nullifierHash,
      content: payload.content,
      attachments: payload.attachments
        ? JSON.stringify(payload.attachments)
        : undefined,
      replyTo: payload.replyTo ? JSON.stringify(payload.replyTo) : undefined,
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

/**
 * Read attachment handles back out of a stored message.
 *
 * A message written before attachments existed has none, and a
 * malformed value yields none rather than throwing — one bad row must
 * not make an entire conversation unreadable.
 */
function parseAttachments(raw: unknown): readonly BlobRef[] | undefined {
  if (typeof raw !== 'string' || raw.length === 0) return undefined;

  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as BlobRef[]) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Read reply references back out of a stored message.
 *
 * A message written before replies existed has none, and a malformed
 * value yields none rather than throwing — one bad row must not make a
 * conversation unreadable.
 */
function parseReplyTo(raw: unknown): readonly string[] | undefined {
  if (typeof raw !== 'string' || raw.length === 0) return undefined;

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return undefined;
    return parsed.every((id) => typeof id === 'string')
      ? (parsed as string[])
      : undefined;
  } catch {
    return undefined;
  }
}
