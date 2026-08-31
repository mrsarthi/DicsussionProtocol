/**
 * @dicsussion/crdt — Type Definitions
 *
 * Document schema, chat message, sync protocol messages,
 * and schema lens types per RFC 002.
 */

/** Multi-document CRDT document metadata. */
export interface DocumentMeta {
  title: string;
  createdAt: number;
  [key: string]: unknown;
}

/**
 * Chat message within a CRDT document.
 * `authorDid` is nullable for anonymous RLN channels (RFC 003/004 cross-spec fix).
 */
export interface ChatMessage {
  id: string;
  authorDid?: string;
  nullifierHash?: string;
  content: string;
  timestamp: number;
  /**
   * Per-channel sequence number assigned by the sender (RFC 002 §4.3).
   *
   * `timestamp` has one-second resolution, so it cannot order messages
   * sent within the same second. This index breaks those ties, giving
   * every replica the same total order.
   */
  messageIndex?: number;
  zkProof?: string;
  rlnNullifier?: string;
  zkEnvelopeRef?: string;
  /**
   * Blob handles this message refers to (Stream `0x09`).
   *
   * Handles only. The bytes live outside the document, which is the
   * point: a picture inlined here would be replicated to everyone in the
   * conversation and kept forever, whether or not anyone opened it.
   *
   * Serialized rather than structured, because Automerge would otherwise
   * treat each handle as a nested map and merge two devices' edits field
   * by field — producing a reference to a blob neither of them has.
   */
  attachments?: string;
  /**
   * Serialized ids of the messages this one replies to.
   *
   * Serialized for the same reason as `attachments`: Automerge would
   * otherwise treat this as a list CRDT and interleave two replicas'
   * edits, producing a reply that names messages nobody sent it to.
   */
  replyTo?: string;
  [key: string]: unknown;
}

/**
 * One person's reaction to one message.
 *
 * Keyed in the document by message and author together, so each person
 * holds exactly one slot per message. That is what makes reacting a
 * *replacement* rather than an append: changing 👍 to ❤️ overwrites,
 * and removing sets `emoji` empty rather than deleting, so the slot's
 * history stays a single value instead of a list of every reaction
 * anyone ever tapped.
 *
 * Only the author writes their own slot, so two replicas never contend
 * for the same one.
 */
export interface ChatReaction {
  messageId: string;
  authorDid: string;
  /** Short opaque string. Empty means the reaction was withdrawn. */
  emoji: string;
  /** Author's clock, for display ordering only. */
  updatedAt: number;
  [key: string]: unknown;
}

/** Schema structure for a chat room CRDT document (RFC 002 §3.1). */
export interface DocumentSchema {
  $schema: string;
  doc_id: string;
  meta: DocumentMeta;
  messages: Record<string, ChatMessage>;
  /**
   * Who this conversation belongs to, keyed by `did:key`.
   *
   * The guest list. Synchronisation shares a document only with peers
   * named here, which is what stops a contact receiving conversations
   * they were never part of.
   *
   * It lives inside the document deliberately, so it survives a device
   * replacement along with the history it governs. The cost is that
   * everyone legitimately holding the document can read it — for a
   * two-party chat that discloses nothing either side does not already
   * know, and for a group it matches what every mainstream messenger
   * shows its members.
   *
   * A document with no entries is shared with nobody.
   */
  participants: Record<string, ParticipantRecord>;
  /**
   * Reactions live at the top level under a `reaction:` prefix, one key
   * per (message, author) pair — not in a nested map.
   *
   * A nested map has to be created before the first reaction can go in
   * it, and two replicas creating it at the same moment produce
   * conflicting assignments of the whole map: Automerge keeps one, and
   * the other person's reaction disappears. Two people reacting to the
   * same message at once is not an edge case.
   *
   * Putting it in the deterministic genesis would also fix that, and
   * would change the genesis bytes — so a node on the older version and
   * one on the newer would mint different genesis for the same channel
   * and fail to merge at all. A prefix costs a scan and breaks nothing.
   */
  [key: string]: unknown;
}

/** A participant's standing in a conversation. */
export interface ParticipantRecord {
  /** Participant's did:key, repeated for convenience when iterating. */
  did: string;
  /** Unix seconds when they were added. */
  addedAt: number;
}

// ─── Sync Protocol Messages (RFC 002 §4.2) ──────────────────────────────────

export interface SparseMerkleRootSync {
  readonly type: 'root_sync';
  readonly rootHash: Uint8Array;
}

export interface RootMatchResponse {
  readonly type: 'root_match';
  readonly matched: boolean;
}

export interface RequestCRDTDelta {
  readonly type: 'request_delta';
  readonly docId: string;
  readonly haveHeads: readonly Uint8Array[];
}

export interface SendCRDTDelta {
  readonly type: 'send_delta';
  readonly docId: string;
  readonly binaryChanges: readonly Uint8Array[];
}

export type SyncMessage =
  | SparseMerkleRootSync
  | RootMatchResponse
  | RequestCRDTDelta
  | SendCRDTDelta;

// ─── Schema Lens Types (RFC 002 §5) ─────────────────────────────────────────

export type LensOperation =
  | { readonly op: 'add_field'; readonly path: string; readonly default: unknown }
  | { readonly op: 'rename_field'; readonly from: string; readonly to: string }
  | { readonly op: 'remove_field'; readonly path: string };

export interface SchemaLens {
  readonly lensId: string;
  readonly fromSchema: string;
  readonly toSchema: string;
  readonly operations: readonly LensOperation[];
}

/** Canonical state fields for Merkle root computation (RFC 002 §4.3). */
export interface CanonicalDocState {
  readonly docId: string;
  readonly headHash: Uint8Array;
  readonly epoch: number;
  readonly messageCount: number;
  readonly quotaWindowId: number;
  readonly messageIndex: number;
}
