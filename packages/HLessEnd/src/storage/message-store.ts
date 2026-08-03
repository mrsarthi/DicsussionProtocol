/**
 * @dicsussion/storage — Message Stream Persistence
 *
 * Writes chat messages to the `message_stream` table (RFC 004 §4.1).
 *
 * The CRDT document remains the authority for channel state; this table
 * is a queryable projection of already-merged state. A failed write is
 * therefore recoverable at the next checkpoint and must never fail the
 * send path.
 */

import type { SdkChatMessage } from '../types.js';
import type { IStorageDriver } from './types.js';
import { StorageCollections } from './types.js';

/**
 * Persists messages and their owning channel rows.
 */
export class MessageStore {
  constructor(private readonly storage: IStorageDriver) {}

  /**
   * Write a message, creating its channel row first.
   *
   * `message_stream` carries a foreign key to `channel_meta`, so the
   * channel must exist before the first message in it lands.
   *
   * @returns True if the write succeeded.
   */
  async save(message: SdkChatMessage): Promise<boolean> {
    try {
      await this.storage.put(StorageCollections.CHANNEL_META, message.channelId, {
        channel_id: message.channelId,
        title: message.channelId,
        peers: '[]',
        access_threshold: 0,
        created_at: message.timestamp,
        last_activity: message.timestamp,
      });

      await this.storage.put(StorageCollections.MESSAGE_STREAM, message.id, {
        id: message.id,
        channel_id: message.channelId,
        author_did: message.authorDid ?? null,
        nullifier_hash: message.nullifierHash ?? null,
        content: message.content,
        timestamp: message.timestamp,
        epoch: message.proofEpoch,
        verified_tier: message.verifiedTier,
        envelope_ref: message.envelopeRef,
      });

      return true;
    } catch {
      // See class doc: the CRDT document is the authority.
      return false;
    }
  }

  /**
   * Read persisted messages for a channel, oldest first.
   *
   * @param channelId The channel to read.
   * @param limit Optional row cap.
   */
  async listByChannel(
    channelId: string,
    limit?: number,
  ): Promise<Record<string, unknown>[]> {
    return this.storage.query(
      StorageCollections.MESSAGE_STREAM,
      { channel_id: channelId },
      limit,
    );
  }
}
