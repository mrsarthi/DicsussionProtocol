/**
 * @dicsussion/storage — Schema Migrations
 *
 * Version-tracked schema migrations for SQLite persistence.
 * Migrations run sequentially and are idempotent.
 */

import type Database from 'better-sqlite3';

export interface Migration {
  readonly version: number;
  readonly description: string;
  readonly up: (db: Database.Database) => void;
}

/** All available migrations in order. */
export const migrations: readonly Migration[] = [
  {
    version: 1,
    description: 'Initial schema — all RFC 004 §4.1 collections',
    up: (db) => {
      db.exec(`
        -- Identity keypairs and secrets
        CREATE TABLE IF NOT EXISTS identity (
          did TEXT PRIMARY KEY,
          ed25519_public_key TEXT NOT NULL,
          ed25519_secret_key_encrypted TEXT NOT NULL,
          x25519_public_key TEXT NOT NULL,
          x25519_secret_key_encrypted TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );

        -- Web-of-Trust peer records
        CREATE TABLE IF NOT EXISTS wot_peers (
          did TEXT PRIMARY KEY,
          verified_sessions INTEGER NOT NULL DEFAULT 0,
          vouchers_redeemed INTEGER NOT NULL DEFAULT 0,
          vouchers_issued INTEGER NOT NULL DEFAULT 0,
          subjective_score INTEGER NOT NULL DEFAULT 0,
          is_blacklisted INTEGER NOT NULL DEFAULT 0,
          last_interaction INTEGER NOT NULL DEFAULT 0
        );

        -- Blind endorsement voucher tracking
        CREATE TABLE IF NOT EXISTS voucher_redeemed (
          nullifier TEXT PRIMARY KEY,
          voucher_ciphertext TEXT NOT NULL,
          redeemed_at INTEGER NOT NULL,
          redeemer_identity_commitment TEXT NOT NULL,
          proof_of_receipt TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );

        -- Channel metadata and access control
        CREATE TABLE IF NOT EXISTS channel_meta (
          channel_id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          peers TEXT NOT NULL DEFAULT '[]',
          access_threshold INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          last_activity INTEGER NOT NULL DEFAULT 0
        );

        -- Message stream with nullable author_did for anonymous RLN channels
        CREATE TABLE IF NOT EXISTS message_stream (
          id TEXT PRIMARY KEY,
          channel_id TEXT NOT NULL,
          author_did TEXT,
          nullifier_hash TEXT,
          content TEXT NOT NULL,
          timestamp INTEGER NOT NULL,
          epoch INTEGER NOT NULL,
          verified_tier INTEGER NOT NULL DEFAULT 0,
          zk_proof BLOB,
          rln_nullifier BLOB,
          envelope_ref TEXT,
          FOREIGN KEY (channel_id) REFERENCES channel_meta(channel_id)
        );

        CREATE INDEX IF NOT EXISTS idx_messages_channel
          ON message_stream(channel_id, timestamp);

        -- Offline outbox queue
        CREATE TABLE IF NOT EXISTS outbox (
          id TEXT PRIMARY KEY,
          channel_id TEXT NOT NULL,
          content TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          proof_epoch INTEGER,
          retry_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_outbox_status
          ON outbox(status);
      `);
    },
  },
  {
    version: 2,
    description: 'Automerge CRDT document snapshots (RFC 002 §4.4)',
    up: (db) => {
      db.exec(`
        -- Compressed Automerge snapshots, checkpointed every 1000 changes
        -- or 7 days. head_hash and message_count are the canonical state
        -- fields used for Merkle root reconciliation (RFC 002 §4.3).
        CREATE TABLE IF NOT EXISTS crdt_documents (
          doc_id TEXT PRIMARY KEY,
          snapshot BLOB NOT NULL,
          head_hash TEXT NOT NULL,
          message_count INTEGER NOT NULL DEFAULT 0,
          updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_crdt_documents_updated
          ON crdt_documents(updated_at);
      `);
    },
  },
  {
    version: 3,
    description: 'ZekPoc identity secrets and blind-signing keys (RFC 004 §4.1)',
    up: (db) => {
      // RFC 004 §4.1 places ZekPoc identity secrets in the identity
      // collection, so these extend the existing table rather than
      // forming a separate one.
      //
      // All values are stored as decimal strings: SQLite INTEGER is
      // 64-bit and would silently truncate a 254-bit field element.
      db.exec(`
        ALTER TABLE identity ADD COLUMN rln_identity_secret TEXT;
        ALTER TABLE identity ADD COLUMN rln_trapdoor TEXT;
        ALTER TABLE identity ADD COLUMN blind_modulus TEXT;
        ALTER TABLE identity ADD COLUMN blind_exponent TEXT;
        ALTER TABLE identity ADD COLUMN blind_private_exponent TEXT;
      `);

      // Redemption nullifiers already spent, so a restarted node still
      // rejects replayed vouchers (RFC 003 §8 ReplayedVoucher).
      db.exec(`
        CREATE TABLE IF NOT EXISTS voucher_nullifiers (
          nullifier TEXT PRIMARY KEY,
          scope TEXT NOT NULL,
          redeemed_at INTEGER NOT NULL
        );
      `);

      // Signed channel genesis anchors (Phase 2A bootstrapping).
      db.exec(`
        CREATE TABLE IF NOT EXISTS genesis_anchors (
          channel_id TEXT PRIMARY KEY,
          creator_did TEXT NOT NULL,
          creator_commitment TEXT NOT NULL,
          initial_root TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          signature BLOB NOT NULL
        );
      `);
    },
  },
  {
    version: 4,
    description: 'BIP-39 recovery phrase storage (RFC 004 §7.3)',
    up: (db) => {
      // The phrase regenerates every derived key, so it is exactly as
      // sensitive as the secret keys beside it — and shares their
      // outstanding requirement for OS-keychain wrapping (RFC 004 §4.1).
      db.exec(`
        ALTER TABLE identity ADD COLUMN mnemonic_encrypted TEXT;
      `);
    },
  },
  {
    version: 5,
    description: 'Channel proof policy in the genesis anchor (RFC 003 §3.4.3)',
    up: (db) => {
      // Defaults to 0 so anchors written before the policy existed keep
      // their effective behaviour. They will still fail signature
      // verification against the v2 encoding, which is correct: their
      // signature never covered a policy, so treating one as signed
      // would be a forgery we performed on the creator's behalf.
      db.exec(`
        ALTER TABLE genesis_anchors
          ADD COLUMN require_proofs INTEGER NOT NULL DEFAULT 0;
      `);
    },
  },
];

/**
 * Run all pending migrations on the database.
 *
 * @param db The SQLite database instance.
 */
export function runMigrations(db: Database.Database): void {
  // Create migrations tracking table
  db.exec(`
    CREATE TABLE IF NOT EXISTS _migrations (
      version INTEGER PRIMARY KEY,
      description TEXT NOT NULL,
      applied_at INTEGER NOT NULL
    );
  `);

  const applied = db
    .prepare('SELECT version FROM _migrations ORDER BY version')
    .all() as { version: number }[];

  const appliedVersions = new Set(applied.map((r) => r.version));

  for (const migration of migrations) {
    if (!appliedVersions.has(migration.version)) {
      db.transaction(() => {
        migration.up(db);
        db.prepare(
          'INSERT INTO _migrations (version, description, applied_at) VALUES (?, ?, ?)',
        ).run(migration.version, migration.description, Math.floor(Date.now() / 1000));
      })();
    }
  }
}
