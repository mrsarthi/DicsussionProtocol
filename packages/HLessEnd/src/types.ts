/**
 * @dicsussion/sdk — Type Definitions
 *
 * Client configuration, network status, and service types
 * per RFC 004 §7.
 */

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
}

/** Real-time network status. */
export interface NetworkStatus {
  readonly connected: boolean;
  readonly peerCount: number;
  readonly relayActive: boolean;
  readonly lastSyncTimestamp: number;
}

/** Options for sending a message. */
export interface SendMessageOptions {
  readonly channelId: string;
  readonly content: string;
}

/** Chat message as returned by the SDK. */
export interface SdkChatMessage {
  readonly id: string;
  readonly channelId: string;
  readonly authorDid?: string;
  readonly nullifierHash?: string;
  readonly content: string;
  readonly timestamp: number;
  readonly verifiedTier: number;
  readonly proofEpoch: number;
  readonly proofValid: boolean;
  readonly envelopeRef: string;
  readonly zkProof?: string;
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
