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
import { SecretBox } from './secret-box.js';
import type { IStorageDriver } from './types.js';
import { StorageCollections } from './types.js';

/**
 * Persists messages and their owning channel rows.
 */
export class MessageStore {
  /**
   * @param box Encryption at rest. Message bodies are the whole point of
   *   the database to anyone who steals it, so they are sealed with the
   *   same key as identity secrets. A pass-through box leaves them
   *   readable, which is what an unconfigured `storageKey` means.
   */
  constructor(
    private readonly storage: IStorageDriver,
    private readonly box: SecretBox = new SecretBox(null),
  ) {}

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
        content: this.box.seal(message.content),
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
    const rows = await this.storage.query(
      StorageCollections.MESSAGE_STREAM,
      { channel_id: channelId },
      limit,
    );

    // Opened on the way out rather than by every caller, so a reader
    // cannot forget and surface ciphertext as though it were a message.
    return rows.map((row) => ({
      ...row,
      content: this.box.open(String(row['content'] ?? '')),
    }));
  }
}
