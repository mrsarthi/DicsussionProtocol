/**
 * @dicsussion/sdk — Type Definitions
 *
 * Client configuration, network status, and service types
 * per RFC 004 §7.
 */

import type { BlobRef } from './blob-service.js';

/** SDK initialization configuration. */
export interface ClientConfig {
  /** Path for SQLite database storage. */
  storagePath?: string;
  /** Ordered list of Iroh DERP relay endpoints. */
  relayEndpoints?: string[];
  /** ZK proof backend: 'wasm' (Node.js) or 'browser' (IndexedDB). */
  proofBackend?: 'wasm' | 'browser';
  /** Logging level. */
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  /** Proof generation timeout in ms (default: 30000). */
  proofTimeoutMs?: number;
  /** Auto-reconnect on disconnection (default: true). */
  autoReconnect?: boolean;
  /** Maximum outbox queue size (default: 1000). */
  maxOutboxSize?: number;
  /**
   * Key encrypting secret key material at rest (RFC 004 §4.1).
   *
   * A 32-byte key or a passphrase. Its provenance is the application's
   * concern — an OS keychain, a user passphrase, or a hardware token all
   * satisfy the requirement.
   *
   * **Required whenever `storagePath` names a real file.** Omitting it
   * throws rather than silently writing identity secrets in the clear.
   * In-memory databases are exempt: there is no file for anyone to read.
   * See `allowUnencryptedStorage` to opt out deliberately.
   */
  storageKey?: Uint8Array | string;
  /**
   * Permit an on-disk database with no encryption at rest.
   *
   * **Never set this in a shipped application.** Without `storageKey` the
   * identity secret — the seed every message key derives from — sits in
   * the SQLite file in plaintext, readable by any process or backup that
   * can open it. Recovering it is a file copy, not an attack.
   *
   * Exists so tests and local debugging can opt in explicitly. The point
   * is that it cannot happen by forgetting.
   */
  allowUnencryptedStorage?: boolean;
  /**
   * Default proof policy for channels **this node creates**.
   *
   * Whether a given message needs a Groth16 proof is decided by the
   * channel's signed genesis anchor, not by this setting — otherwise two
   * peers with different-but-valid configs partition silently, the
   * stricter dropping everything the laxer sends. This value only
   * chooses what `createGroup` writes into new anchors, and
   * `createGroup(..., { requireProofs })` overrides it per channel.
   *
   * Proving costs ~1s per anonymous message: worth it on an open channel
   * where "some member in good standing sent this" is the only available
   * claim, wasteful in a two-person chat.
   */
  zkProofs?: 'off' | 'anonymous';
  /**
   * Explicit circuit artifact paths.
   *
   * Omit to resolve them from the installed package. Only relevant when
   * `zkProofs` is enabled.
   */
  proofArtifacts?: {
    readonly wasmPath: string;
    readonly zkeyPath: string;
    readonly verificationKeyPath: string;
  };
  /**
   * Permit a proving key from a single-party development ceremony.
   *
   * **Never set this in a shipped application.** Such a key lets whoever
   * generated it forge channel membership, reputation tier, and
   * unlimited messages past the rate limit — all verifying perfectly, so
   * nothing appears wrong. It exists so tests can run before a real
   * ceremony has happened.
   *
   * The ceremony behind the shipped key, with every contribution hash
   * and the beacon commitment, is published at
   * github.com/mrsarthi/Ceremonial-Contributions.
   */
  allowDevelopmentCeremony?: boolean;
}

/** Real-time network status. */
export interface NetworkStatus {
  readonly connected: boolean;
  readonly peerCount: number;
  readonly relayActive: boolean;
  readonly lastSyncTimestamp: number;
}

/** A peer that has completed the handshake. */
export interface PeerConnectedEvent {
  /**
   * The peer's did:key, proven by the RFC 001 §5 handshake.
   *
   * Proven, but not *trusted*: the handshake shows the far side holds the
   * secret behind this identifier, not that it is anyone you know.
   */
  readonly peerDid: string;
  /**
   * Whether this peer was paired out of band (RFC 001 §3.3).
   *
   * `false` means a stranger completed a handshake. They can send
   * nothing and receive nothing until paired.
   */
  readonly paired: boolean;
  /** Whether we dialled them, or they dialled us. */
  readonly direction: 'outbound' | 'inbound';
}

/** A peer's connection ended. */
export interface PeerDisconnectedEvent {
  /** The peer's did:key. */
  readonly peerDid: string;
  /** Unix seconds when the connection ended. */
  readonly at: number;
}

/** Options for sending a message. */
export interface SendMessageOptions {
  readonly channelId: string;
  readonly content: string;
  /**
   * Blobs this message refers to, from `client.blobs.put()`.
   *
   * Only the handles are sent. A recipient fetches the bytes when they
   * want them, so an attachment nobody opens never crosses the wire.
   */
  readonly attachments?: readonly BlobRef[];
  /**
   * Ids of messages this one replies to.
   *
   * Carried as its own field so a reply is structured data rather than a
   * marker inside `content` — which every client would have to know to
   * strip, forever, and which renders as literal text in any that does
   * not.
   *
   * Ids are not resolved or checked. A reply may legitimately arrive
   * before the message it answers, or name one this device never
   * received, so a reference that resolves to nothing is a rendering
   * decision rather than an error.
   */
  readonly replyTo?: readonly string[];
  /**
   * Who this conversation belongs to, as `did:key`s.
   *
   * Used only when the channel does not exist yet — the first message
   * is what brings it into being, so it is the one moment membership
   * can be established. The sender is always included.
   *
   * **Omitting this creates a conversation shared with nobody.** That is
   * deliberate: the SDK cannot infer who a channel is for, and guessing
   * is how a contact ends up receiving conversations they were never
   * part of. Declare it, or the messages stay on this device.
   */
  readonly participants?: readonly string[];
  /**
   * Send without attributing the message to this node's did:key.
   *
   * The message carries a `nullifierHash` instead of an `authorDid`
   * (RFC 003 §4.1), so recipients can enforce rate limits and detect
   * double-sends without learning who sent it. Requires the RLN engine;
   * throws if no anonymous signal source is attached.
   */
  readonly anonymous?: boolean;
}

/** Chat message as returned by the SDK. */
export interface SdkChatMessage {
  readonly id: string;
  readonly channelId: string;
  readonly authorDid?: string;
  readonly nullifierHash?: string;
  readonly content: string;
  /** Blob handles this message refers to; fetch with `client.blobs.get()`. */
  readonly attachments?: readonly BlobRef[];
  /**
   * Ids of messages this one replies to.
   *
   * May name a message this device does not hold — resolve against
   * `getHistory()` and decide what to show when it is absent.
   */
  readonly replyTo?: readonly string[];
  readonly timestamp: number;
  readonly verifiedTier: number;
  readonly proofEpoch: number;
  readonly proofValid: boolean;
  readonly envelopeRef: string;
  readonly zkProof?: string;
}

/**
 * Longest reaction accepted, in UTF-16 code units.
 *
 * Generous, because a single emoji is often several code points — skin
 * tones and ZWJ sequences run long — and short enough that a reaction
 * cannot become a message in disguise.
 */
export const MAX_REACTION_LENGTH = 32;

/** Reactions to one message, grouped by what people chose. */
export interface ReactionSummary {
  readonly emoji: string;
  readonly count: number;
  /** Who reacted, sorted, so the same set renders identically. */
  readonly reactors: readonly string[];
  /** Whether this device's identity is among them. */
  readonly mine: boolean;
}

/** A reaction was added, changed, or withdrawn. */
export interface ReactionEvent {
  readonly channelId: string;
  readonly messageId: string;
  readonly authorDid: string;
  /** Empty when withdrawn; `removed` says so without a string compare. */
  readonly emoji: string;
  readonly removed: boolean;
}

/** Group information. */
export interface GroupInfo {
  readonly groupId: string;
  readonly name: string;
  readonly members: readonly string[];
  readonly createdAt: number;
}

/** Group invite notification. */
export interface GroupInvite {
  readonly groupId: string;
  readonly name: string;
  readonly inviterDid: string;
  readonly timestamp: number;
}

/** Identity information. */
export interface Identity {
  readonly did: string;
  readonly publicKey: string;
  readonly createdAt: number;
}
