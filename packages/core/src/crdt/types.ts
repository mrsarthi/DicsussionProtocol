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
  [key: string]: unknown;
}

/** Schema structure for a chat room CRDT document (RFC 002 §3.1). */
export interface DocumentSchema {
  $schema: string;
  doc_id: string;
  meta: DocumentMeta;
  messages: Record<string, ChatMessage>;
  [key: string]: unknown;
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
