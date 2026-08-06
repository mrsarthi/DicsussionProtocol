/**
 * @dicsussion/storage — Type Definitions
 *
 * Storage driver interface, record schemas, and outbox entry types
 * per RFC 004 §4.
 */

/** Abstract storage driver interface for SQLite/IndexedDB backends. */
export interface IStorageDriver {
  /** Initialize the storage (create tables, run migrations). */
  initialize(): Promise<void>;

  /** Store a record in a collection. */
  put(collection: string, key: string, value: Record<string, unknown>): Promise<void>;

  /** Retrieve a record from a collection. */
  get(collection: string, key: string): Promise<Record<string, unknown> | undefined>;

  /** Delete a record from a collection. */
  delete(collection: string, key: string): Promise<boolean>;

  /** Query records from a collection with optional filter. */
  query(
    collection: string,
    filter?: Record<string, unknown>,
    limit?: number,
  ): Promise<Record<string, unknown>[]>;

  /** Close the storage connection. */
  close(): Promise<void>;
}

/** RFC 004 §4.1 — Identity record (keypairs, secrets, mnemonic backups). */
export interface IdentityRecord {
  readonly did: string;
  readonly ed25519PublicKey: string;
  readonly ed25519SecretKeyEncrypted: string;
  readonly x25519PublicKey: string;
  readonly x25519SecretKeyEncrypted: string;
  readonly createdAt: number;
}

/** RFC 004 §4.1 — WoT peer record (interaction counters, trust scores). */
export interface WotPeerRecord {
  readonly did: string;
  readonly verifiedSessions: number;
  readonly vouchersRedeemed: number;
  readonly vouchersIssued: number;
  readonly subjectiveScore: number;
  readonly isBlacklisted: boolean;
  readonly lastInteraction: number;
}

/** RFC 004 §7.5 — Voucher record (redemption tracking). */
export interface VoucherRecord {
  readonly nullifier: string;
  readonly voucherCiphertext: string;
  readonly redeemedAt: number;
  readonly redeemerIdentityCommitment: string;
  readonly proofOfReceipt: string;
  readonly expiresAt: number;
}

/** RFC 004 §4.1 — Channel metadata record. */
export interface ChannelMetaRecord {
  readonly channelId: string;
  readonly title: string;
  readonly peers: readonly string[];
  readonly accessThreshold: number;
  readonly createdAt: number;
  readonly lastActivity: number;
}

/** RFC 004 §4.1 — Message stream record. */
export interface MessageRecord {
  readonly id: string;
  readonly channelId: string;
  readonly authorDid?: string;
  readonly nullifierHash?: string;
  readonly content: string;
  readonly timestamp: number;
  readonly epoch: number;
  readonly verifiedTier: number;
  readonly zkProof?: string;
  readonly rlnNullifier?: string;
  readonly envelopeRef?: string;
}

/** RFC 004 §7.4 — Offline outbox entry. */
export interface OutboxEntry {
  readonly id: string;
  readonly channelId: string;
  readonly content: string;
  readonly createdAt: number;
  readonly status: 'pending' | 'sending' | 'failed' | 'sent';
  readonly proofEpoch?: number;
  readonly retryCount: number;
}

/** Storage collection names matching RFC 004 §4.1. */
export const StorageCollections = {
  IDENTITY: 'identity',
  WOT_PEERS: 'wot_peers',
  VOUCHER_REDEEMED: 'voucher_redeemed',
  CHANNEL_META: 'channel_meta',
  MESSAGE_STREAM: 'message_stream',
  OUTBOX: 'outbox',
  /** Automerge snapshots (RFC 002 §4.4). */
  CRDT_DOCUMENTS: 'crdt_documents',
  /** Spent redemption nullifiers (RFC 003 §8). */
  VOUCHER_NULLIFIERS: 'voucher_nullifiers',
  /** Signed channel genesis anchors. */
  GENESIS_ANCHORS: 'genesis_anchors',
} as const;
