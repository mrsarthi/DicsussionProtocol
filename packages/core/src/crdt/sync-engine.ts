/**
 * @dicsussion/crdt — Automerge State Sync Engine (Stream 0x01)
 *
 * Drives the RFC 002 §4.2 reconciliation sequence over Sub-Stream `0x01`:
 *
 *   1. Advertise the canonical state root.
 *   2. If roots match, stop — zero bytes of history are transferred.
 *   3. Otherwise exchange Automerge sync messages until both replicas
 *      converge on identical heads.
 *
 * The engine is transport-agnostic: it consumes inbound `0x01` payloads
 * and returns the payloads to send back. Wiring those to a connection is
 * the caller's job, which keeps this module free of socket concerns.
 */

import * as Automerge from '@automerge/automerge';

import type { DocumentManager } from './document-manager.js';
import { computeManagerStateRoot, rootsEqual } from './state-root.js';
import type { SyncFrame } from './sync-protocol.js';
import {
  decodeBoolBody,
  decodeSyncFrame,
  encodeBoolBody,
  encodeSyncFrame,
  SyncMessageType,
} from './sync-protocol.js';
import type { DocumentSchema } from './types.js';

/** Emitted when a peer's changes advance a local document. */
export interface DocumentUpdate {
  readonly peerId: string;
  readonly docId: string;
  /** Heads after applying the peer's changes. */
  readonly heads: readonly string[];
}

export type DocumentUpdateHandler = (update: DocumentUpdate) => void;

/** Per-peer Automerge sync state, keyed by document id. */
type PeerSyncStates = Map<string, Automerge.SyncState>;

/**
 * Reconciles Automerge documents with remote peers over Stream 0x01.
 */
export class CrdtSyncEngine {
  private readonly peerStates = new Map<string, PeerSyncStates>();
  private readonly updateHandlers = new Set<DocumentUpdateHandler>();

  constructor(private readonly documents: DocumentManager) {}

  /** Peers currently tracked by the engine. */
  get peerCount(): number {
    return this.peerStates.size;
  }

  /** Begin tracking sync state for a peer. Idempotent. */
  registerPeer(peerId: string): void {
    if (!this.peerStates.has(peerId)) {
      this.peerStates.set(peerId, new Map());
    }
  }

  /** Drop all sync state for a disconnected peer. */
  removePeer(peerId: string): void {
    this.peerStates.delete(peerId);
  }

  /** Subscribe to documents advanced by remote changes. */
  onDocumentUpdate(handler: DocumentUpdateHandler): () => void {
    this.updateHandlers.add(handler);
    return () => {
      this.updateHandlers.delete(handler);
    };
  }

  /** The local canonical state root (RFC 002 §4.3). */
  stateRoot(): Uint8Array {
    return computeManagerStateRoot(this.documents);
  }

  /**
   * Produce the opening ROOT_SYNC advertisement for a peer.
   *
   * @returns An encoded Stream 0x01 payload.
   */
  beginSync(peerId: string): Uint8Array {
    this.registerPeer(peerId);
    return encodeSyncFrame(SyncMessageType.ROOT_SYNC, '', this.stateRoot());
  }

  /**
   * Produce sync messages pushing a specific document to a peer.
   *
   * @returns Encoded payloads, or an empty array if already in sync.
   */
  syncDocument(peerId: string, docId: string): Uint8Array[] {
    this.registerPeer(peerId);
    const message = this.generateFor(peerId, docId);
    return message ? [message] : [];
  }

  /**
   * Handle one inbound Stream 0x01 payload.
   *
   * @param peerId The sending peer's identifier.
   * @param payload Raw `0x01` frame payload.
   * @returns Payloads to send back, in order. Empty means "nothing to say".
   */
  handleMessage(peerId: string, payload: Uint8Array): Uint8Array[] {
    this.registerPeer(peerId);

    const frame = decodeSyncFrame(payload);

    switch (frame.type) {
      case SyncMessageType.ROOT_SYNC:
        return this.handleRootSync(peerId, frame);
      case SyncMessageType.ROOT_MATCH:
        return this.handleRootMatch(peerId, frame);
      case SyncMessageType.REQUEST_DELTA:
        return this.handleRequestDelta(peerId, frame);
      case SyncMessageType.SEND_DELTA:
        return this.handleSendDelta(peerId, frame);
      default:
        return [];
    }
  }

  /**
   * Peer advertised its root. Compare against ours and either confirm a
   * match (zero further bytes) or open document sync.
   */
  private handleRootSync(peerId: string, frame: SyncFrame): Uint8Array[] {
    const matched = rootsEqual(frame.body, this.stateRoot());

    const reply = [
      encodeSyncFrame(SyncMessageType.ROOT_MATCH, '', encodeBoolBody(matched)),
    ];

    if (matched) return reply;

    return [...reply, ...this.generateAllDocumentMessages(peerId)];
  }

  /** Peer answered our advertisement; push documents when roots differ. */
  private handleRootMatch(peerId: string, frame: SyncFrame): Uint8Array[] {
    if (decodeBoolBody(frame.body)) return [];
    return this.generateAllDocumentMessages(peerId);
  }

  /** Peer explicitly asked for a document's changes. */
  private handleRequestDelta(peerId: string, frame: SyncFrame): Uint8Array[] {
    const message = this.generateFor(peerId, frame.docId);
    return message ? [message] : [];
  }

  /**
   * Apply a peer's Automerge sync message, then answer with whatever the
   * protocol still needs to converge.
   */
  private handleSendDelta(peerId: string, frame: SyncFrame): Uint8Array[] {
    const { docId } = frame;
    const states = this.peerStates.get(peerId)!;

    const doc = this.documents.ensureSyncDocument(docId);
    const syncState = states.get(docId) ?? Automerge.initSyncState();

    const headsBefore = Automerge.getHeads(doc).join(',');

    // `frame.body` is a zero-copy view; Automerge needs an owned buffer.
    const [nextDoc, nextState] = Automerge.receiveSyncMessage(
      doc,
      syncState,
      frame.body.slice() as Automerge.SyncMessage,
    );

    states.set(docId, nextState);
    this.documents.replaceDocument(docId, nextDoc as Automerge.Doc<DocumentSchema>);

    const headsAfter = Automerge.getHeads(nextDoc);
    if (headsAfter.join(',') !== headsBefore) {
      this.emitUpdate({ peerId, docId, heads: headsAfter as string[] });
    }

    const reply = this.generateFor(peerId, docId);
    return reply ? [reply] : [];
  }

  /** Emit one SEND_DELTA per known document that still needs pushing. */
  private generateAllDocumentMessages(peerId: string): Uint8Array[] {
    const messages: Uint8Array[] = [];

    for (const docId of this.documents.listDocuments()) {
      const message = this.generateFor(peerId, docId);
      if (message) messages.push(message);
    }

    return messages;
  }

  /**
   * Ask Automerge for the next sync message for (peer, document).
   *
   * @returns An encoded SEND_DELTA payload, or null when converged.
   */
  private generateFor(peerId: string, docId: string): Uint8Array | null {
    const states = this.peerStates.get(peerId)!;
    const doc = this.documents.getDocument(docId);
    if (!doc) return null;

    const syncState = states.get(docId) ?? Automerge.initSyncState();
    const [nextState, message] = Automerge.generateSyncMessage(doc, syncState);
    states.set(docId, nextState);

    if (!message) return null;

    return encodeSyncFrame(
      SyncMessageType.SEND_DELTA,
      docId,
      message as unknown as Uint8Array,
    );
  }

  private emitUpdate(update: DocumentUpdate): void {
    for (const handler of this.updateHandlers) {
      handler(update);
    }
  }
}
