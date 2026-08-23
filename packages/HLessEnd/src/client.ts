/**
 * @dicsussion/sdk — DicsussionClient
 *
 * Main facade API orchestrating transport, crypto, CRDT, storage,
 * and WoT modules per RFC 004 §7.1.
 *
 * Bootstrap order matters: storage first (so identity and outbox can be
 * restored), then identity, then transport, then CRDT sync, then an
 * outbox flush for anything queued before the last shutdown.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { Emitter } from '@dicsussion/core/transport';
import type { BlindPublicKey } from '@dicsussion/core/crypto';
import { fieldToHex, hexToField } from '@dicsussion/core/crypto';
import {
  createSignal,
  isWithinQuota,
  resolveArtifacts,
} from '@dicsussion/core/zk';
import type { RlnSignal } from '@dicsussion/core/zk';
import { StreamType } from '@dicsussion/core/transport';
import { DocumentManager } from '@dicsussion/core/crdt';
import { CrdtSyncEngine } from '@dicsussion/core/crdt';
import { MembershipSyncEngine } from '@dicsussion/core/crdt';
import { IrohTransport } from '@dicsussion/core/transport';
import type { ITransport } from '@dicsussion/core/transport';
import type { WebSocketLike } from '@dicsussion/core/transport';
import type { MdnsDiscovery } from '@dicsussion/core/transport';
import type { IDatagramSocket } from '@dicsussion/core/transport';
import type { DiscoveredPeer } from '@dicsussion/core/transport';
import type { IConnection } from '@dicsussion/core/transport';
import type { PeerTicket } from '@dicsussion/core/transport';
import { ChatService } from './chat-service.js';
import { ProofService } from './proof-service.js';
import { GroupService } from './group-service.js';
import { IdentityService } from './identity-service.js';
import type { LocalIdentity } from './identity-service.js';
import { currentEpoch, OutboxManager } from './outbox.js';
import { PeerRegistry } from './peer-registry.js';
import type { MessagePayload } from './message-codec.js';
import { SessionManager } from './session-manager.js';
import {
  initDiscovery,
  initIdentity,
  initStorage,
  initTransport,
} from './engine-bootstrap.js';
import type { TransportFactory } from './engine-bootstrap.js';
import type { DocumentStore } from './storage/document-store.js';
import type { MessageStore } from './storage/message-store.js';
import type { IStorageDriver } from './storage/types.js';
import { TrustService } from './trust-service.js';
import { createSlashingStack } from './slashing/slashing-bootstrap.js';
import type {
  SlashingCoordinator,
  SlashingEvent,
} from './slashing/slashing-coordinator.js';
import type { ObservedShare } from './slashing/share-collector.js';
import type { GenesisAnchor } from './wot/genesis-anchor.js';
import { verifyGenesisAnchor } from './wot/genesis-anchor.js';
import { createTrustStack } from './wot/trust-bootstrap.js';
import type { VoucherStore } from './wot/voucher-store.js';
import type { VoucherHandshake } from './wot/voucher-handshake.js';
import type { IssuanceRecord, VoucherService } from './wot/voucher-service.js';
import type {
  ClientConfig,
  NetworkStatus,
  PeerConnectedEvent,
} from './types.js';

/** A transport that knows how it is reachable and can publish a ticket. */
interface TicketProvider {
  getTicket(): PeerTicket;
}

/** Extra options that are test/embedding seams rather than user config. */
export interface ClientRuntimeOptions {
  /** UDP port advertised in mDNS beacons. */
  readonly discoveryPort?: number;
  /** Datagram backend for mDNS; omit to use real multicast. */
  readonly discoverySocket?: IDatagramSocket;
  /** Enable mDNS beaconing (default: false — opt in explicitly). */
  readonly enableDiscovery?: boolean;
  /** Override the mDNS beacon interval. */
  readonly beaconIntervalMs?: number;
  /**
   * Transport backend.
   *
   * `'local'` (default) is in-process and needs no native module.
   * `'iroh'` is real QUIC. `'websocket'` routes through a relay and is
   * the only backend a browser can use. An `ITransport` instance can
   * also be supplied directly.
   */
  readonly transport?:
    | 'local'
    | 'iroh'
    | 'websocket'
    | ITransport
    | TransportFactory;
  /** Relay endpoint, required by the `'websocket'` backend. */
  readonly relayUrl?: string;
  /** Socket factory for the `'websocket'` backend. */
  readonly createSocket?: (url: string) => WebSocketLike;
  /** Bind address for the Iroh backend, e.g. `127.0.0.1:0`. */
  readonly bindAddr?: string;
  /** Disable relays and discovery on the Iroh backend (tests). */
  readonly localOnly?: boolean;
  /**
   * Storage backend, replacing the default SQLite driver.
   *
   * Supply `IndexedDbDriver` to run inside a browser or webview, where
   * `better-sqlite3` is a NAPI module that cannot load. Pass an
   * uninitialised instance — the client opens it during bootstrap.
   */
  readonly storage?: IStorageDriver;
}

/**
 * Primary public API for the Dicsussion protocol engine.
 *
 * Application frontends import this class to access chat, group,
 * identity, and trust features without managing low-level internals.
 */
export class DicsussionClient {
  public readonly chat: ChatService;
  public readonly groups: GroupService;
  public readonly trust: TrustService;
  public readonly identity: IdentityService;
  public readonly onNetworkStatus = new Emitter<{ status: [NetworkStatus] }>();

  /**
   * A peer completed the RFC 001 §5 handshake, paired or not.
   *
   * Fires for connections in both directions. `paired` is the field that
   * matters: a completed handshake proves only that the far side holds
   * the secret behind the `did:key` it asserted, which any stranger can
   * arrange with a fresh keypair. An unpaired peer has no protocol
   * surface — it cannot sync, and its messages are dropped — so this
   * event exists for applications that want to surface the request
   * rather than discard it silently.
   *
   * @see {@link DicsussionClient.addPeer} to accept one.
   */
  public readonly onPeerConnected = new Emitter<{
    peer: [PeerConnectedEvent];
  }>();

  private readonly outbox: OutboxManager;
  private readonly config: Required<Omit<ClientConfig, 'proofArtifacts'>> &
    Pick<ClientConfig, 'proofArtifacts'>;
  private readonly runtime: ClientRuntimeOptions;
  private readonly documents = new DocumentManager();
  private readonly peers = new PeerRegistry();
  private readonly syncEngine: CrdtSyncEngine;
  private readonly membershipSync: MembershipSyncEngine;
  private readonly sessions: SessionManager;

  private storage: IStorageDriver | null = null;
  private documentStore: DocumentStore | null = null;
  private messageStore: MessageStore | null = null;
  private voucherService: VoucherService | null = null;
  private voucherHandshake: VoucherHandshake | null = null;
  private voucherStore: VoucherStore | null = null;
  /** RLN signal from the most recent anonymous send, for share gossip. */
  private lastAnonymousSignal: RlnSignal | null = null;
  private slashing: SlashingCoordinator | null = null;
  /** Groth16 prover, present only when circuit artifacts are available. */
  private proofs: ProofService | null = null;
  private transport: ITransport | null = null;
  private discovery: MdnsDiscovery | null = null;
  private localIdentity: LocalIdentity | null = null;
  private online = true;

  private constructor(config: ClientConfig, runtime: ClientRuntimeOptions) {
    this.config = {
      storagePath: config.storagePath ?? ':memory:',
      relayEndpoints: config.relayEndpoints ?? [],
      proofBackend: config.proofBackend ?? 'wasm',
      logLevel: config.logLevel ?? 'info',
      proofTimeoutMs: config.proofTimeoutMs ?? 30_000,
      autoReconnect: config.autoReconnect ?? true,
      maxOutboxSize: config.maxOutboxSize ?? 1000,
      storageKey: config.storageKey ?? '',
      zkProofs: config.zkProofs ?? 'off',
      proofArtifacts: config.proofArtifacts,
      allowDevelopmentCeremony: config.allowDevelopmentCeremony ?? false,
      allowUnencryptedStorage: config.allowUnencryptedStorage ?? false,
    };

    // Fail closed on at-rest encryption.
    //
    // Previously omitting `storageKey` logged a warning and wrote identity
    // secrets in plaintext. A warning is not a control: it scrolls past in
    // development and is absent from production logs nobody reads, so the
    // failure mode was an application shipping with the seed every message
    // key derives from sitting readable in its SQLite file.
    //
    // In-memory databases are exempt — there is no file to protect — which
    // keeps tests and evaluation frictionless while making the unsafe
    // on-disk case impossible to reach by accident.
    if (
      this.config.storagePath !== ':memory:' &&
      this.config.storageKey.length === 0 &&
      !this.config.allowUnencryptedStorage
    ) {
      throw new Error(
        'storageKey is required when storagePath writes to disk: identity ' +
          'secrets would otherwise be stored in plaintext (RFC 004 §4.1). ' +
          'Pass a 32-byte key or passphrase, use storagePath: ":memory:", ' +
          'or set allowUnencryptedStorage: true to accept the risk.',
      );
    }
    this.runtime = runtime;

    this.chat = new ChatService();
    this.groups = new GroupService();
    this.trust = new TrustService();
    this.identity = new IdentityService();
    this.outbox = new OutboxManager(this.config.maxOutboxSize);
    // Deny-by-default authorization for synchronisation. Pairing means
    // "we agreed to talk", not "you may read every conversation I hold";
    // without this a sync offered whatever the node happened to have, so
    // a second contact received the first one's history, backdated.
    this.syncEngine = new CrdtSyncEngine(this.documents, (peerDid, docId) =>
      this.documents.isParticipant(docId, peerDid),
    );
    this.membershipSync = new MembershipSyncEngine((channelId) =>
      this.groups.getMembershipTree(channelId),
    );
    this.sessions = new SessionManager({
      peers: this.peers,
      // The same boundary on the direct send path. Publishing fanned a
      // message out to every paired peer whatever channel it belonged
      // to, which leaked conversations quite apart from synchronisation.
      mayReceive: (peerDid, channelId) =>
        this.documents.isParticipant(channelId, peerDid),
      knowsChannel: (channelId) => this.documents.hasDocument(channelId),
      syncEngine: this.syncEngine,
      membershipSync: this.membershipSync,
      onMessage: async (payload) => {
        await this.chat.ingestRemote(payload);
      },
      onVoucherFrame: async (payload, connection) => {
        await this.voucherHandshake?.handleMessage(payload, connection);
      },
      onShareFrame: async (payload) => {
        await this.slashing?.handleShareFrame(payload);
      },
      onRevocationFrame: async (payload) => {
        await this.slashing?.handleTombstoneFrame(payload);
      },
      onSignalFrame: async (payload) => {
        // An RLN signal is a share broadcast without an accompanying
        // message, so it feeds the same detector.
        await this.slashing?.handleShareFrame(payload);
      },
    });
  }

  /**
   * Initialize a new DicsussionClient instance.
   * Sets up internal engine, storage, and transport.
   *
   * @param config Optional configuration overrides.
   * @param runtime Optional test/embedding seams.
   * @returns A fully initialized client ready for use.
   */
  public static async init(
    config: ClientConfig = {},
    runtime: ClientRuntimeOptions = {},
  ): Promise<DicsussionClient> {
    assertCryptoAvailable();

    const client = new DicsussionClient(config, runtime);
    await client.bootstrapInternalEngine();

    return client;
  }

  // ─── Identity & addressing ────────────────────────────────────────────

  /** This node's did:key identifier. */
  get did(): string {
    return this.requireIdentity().did;
  }

  /** This node's X25519 public key, shared during out-of-band pairing. */
  get encryptionPublicKey(): Uint8Array {
    return this.requireIdentity().encryption.publicKey;
  }

  /**
   * A connection ticket other peers can dial (RFC 001 §3.3).
   *
   * With a real transport the ticket carries live socket addresses and
   * the Iroh `EndpointId`, so it must come from the transport rather
   * than being synthesised from identity alone.
   */
  getTicket(): PeerTicket {
    const identity = this.requireIdentity();
    const transport = this.transport;

    // A capability check, not `instanceof`: any transport that knows how
    // it is reachable can publish a dialable ticket, including a bridged
    // one supplied by a non-Node host. `instanceof IrohTransport` would
    // silently hand those callers an address-less ticket instead.
    const provider = transport as Partial<TicketProvider> | null;

    const base: PeerTicket =
      typeof provider?.getTicket === 'function'
        ? provider.getTicket()
        : {
            didKey: identity.did,
            nodeId: identity.signing.publicKey,
            directAddresses: [],
            derpRelay: this.config.relayEndpoints[0],
          };

    // A ticket is a pairing artifact, so it carries the E2EE key too.
    return { ...base, encryptionKey: identity.encryption.publicKey };
  }

  // ─── Peering ──────────────────────────────────────────────────────────

  /**
   * Record a peer's E2EE public key, learned out of band.
   *
   * Must be called before messages can be encrypted for that peer.
   */
  addPeer(did: string, encryptionPublicKey: Uint8Array): void {
    this.peers.addPeer(did, encryptionPublicKey);
  }

  /**
   * Dial a peer, complete the handshake, and begin CRDT sync.
   *
   * @param ticket The peer's connection ticket.
   */
  async connect(ticket: PeerTicket): Promise<IConnection> {
    const transport = this.requireTransport();

    // A ticket that carries an encryption key is self-pairing; otherwise
    // the caller must have registered the peer beforehand.
    if (!this.peers.getPeer(ticket.didKey)) {
      if (!ticket.encryptionKey) {
        throw new Error(
          `Unknown peer ${ticket.didKey}. Call addPeer() with their X25519 key first.`,
        );
      }
      this.peers.addPeer(ticket.didKey, ticket.encryptionKey);
    }

    const connection = await transport.connect(ticket);
    this.sessions.registerConnection(connection);
    this.announcePeer(connection.peerDid, 'outbound');
    await this.sessions.beginSync(connection);
    await this.drainAfterReconnect();

    return connection;
  }

  /**
   * Release dead connections and send anything the outbox is holding.
   *
   * A queued message is only half a recovery; something has to notice
   * the peer is back. Reconnection is that moment, and it arrives from
   * either direction — we dial them, or they dial us — so both paths
   * come through here.
   *
   * Never throws: a peer that is reachable again but fails mid-flush
   * leaves its entries queued for the next attempt, and must not turn a
   * successful connection into a rejected one.
   */
  private async drainAfterReconnect(): Promise<void> {
    try {
      this.peers.pruneDisconnected();
      if (this.outbox.getPending().length > 0) await this.flushOutbox();
    } catch {
      // Entries stay queued; the next reconnection retries them.
    }
  }

  /** Tell listeners a peer handshake completed, and whether it counts. */
  private announcePeer(
    peerDid: string,
    direction: PeerConnectedEvent['direction'],
  ): void {
    this.onPeerConnected.emit('peer', {
      peerDid,
      paired: this.peers.getPeer(peerDid)?.paired === true,
      direction,
    });
  }

  // ─── Web-of-Trust (RFC 003 §5, RFC 004 §6) ────────────────────────────

  /** This node's Poseidon identity commitment `cm_identity`. */
  get identityCommitment(): bigint {
    return this.requireIdentity().commitment;
  }

  /**
   * This node's RSA blind-signing public key.
   *
   * Shared during pairing so peers can blind voucher requests to us.
   *
   * Async because the keypair is generated on first use rather than at
   * `init()` — RSA-2048 keygen costs hundreds of milliseconds to
   * seconds, and most nodes never issue an endorsement at all. The first
   * call pays that cost once and persists the result.
   */
  async getEndorsementKey(): Promise<BlindPublicKey> {
    const keypair = await this.identity.ensureBlindKeypair();

    // The voucher service was built before the key existed, so hand it
    // over now — otherwise `canIssue` stays false and we would decline
    // requests using a key we actually hold.
    this.voucherService?.setIssuerKeypair(keypair);

    return { n: keypair.n, e: keypair.e };
  }

  /**
   * Ask a connected peer to gift a +5 POC endorsement voucher.
   *
   * Runs the synchronous Stream 0x04 handshake, unblinds the result, and
   * redeems it locally — raising *our* subjective score for that peer,
   * since they are the one who vouched for us.
   *
   * @param peerDid The issuing peer.
   * @param issuerEndorsementKey The peer's RSA public key, from pairing.
   * @param scope Redemption scope bound into the nullifier.
   * @returns True if the voucher was issued and redeemed.
   */
  async requestEndorsement(
    peerDid: string,
    issuerEndorsementKey: BlindPublicKey,
    scope: bigint = 0n,
  ): Promise<boolean> {
    const handshake = this.voucherHandshake;
    if (!handshake) {
      throw new Error('Web-of-Trust stack is not initialised');
    }

    const connection = this.peers.getPeer(peerDid)?.connection;
    if (!connection) {
      throw new Error(`No live connection to ${peerDid}`);
    }

    const token = await handshake.request(
      connection,
      issuerEndorsementKey,
      scope,
    );
    return this.trust.redeemVoucher(token, peerDid);
  }

  /**
   * Persist a channel's signed genesis anchor.
   *
   * The anchor is verified before storage — an unverifiable anchor is a
   * forgery attempt, not a record worth keeping.
   *
   * @throws If the anchor's signature does not match its claimed creator.
   */
  saveGenesisAnchor(anchor: GenesisAnchor): void {
    if (!this.voucherStore) {
      throw new Error('Web-of-Trust stack is not initialised');
    }
    if (!verifyGenesisAnchor(anchor)) {
      throw new Error(
        `Refusing to persist genesis anchor for ${anchor.channelId}: signature verification failed`,
      );
    }

    this.voucherStore.saveAnchor(anchor);
  }

  /** Load a channel's persisted genesis anchor. */
  getGenesisAnchor(channelId: string): GenesisAnchor | undefined {
    return this.voucherStore?.loadAnchor(channelId);
  }

  /** Every persisted genesis anchor. */
  listGenesisAnchors(): GenesisAnchor[] {
    return this.voucherStore?.loadAllAnchors() ?? [];
  }

  /** Count of redemption nullifiers this node has durably spent. */
  get spentVoucherCount(): number {
    return this.voucherStore?.countNullifiers() ?? 0;
  }

  /**
   * Publish an RLN share so peers can police this node's quota.
   *
   * Broadcasting our own shares is what makes the scheme symmetric — a
   * node that withheld them could overspend undetected.
   */
  async broadcastRlnShare(share: ObservedShare): Promise<void> {
    await this.slashing?.broadcastShare(share);
  }

  /** The share from the most recent anonymous send, if any. */
  getLastRlnSignal(): RlnSignal | null {
    return this.lastAnonymousSignal;
  }

  /** Subscribe to slashing events observed or authored by this node. */
  onSlashing(handler: (event: SlashingEvent) => void): () => void {
    return this.slashing?.onSlashing(handler) ?? (() => undefined);
  }

  /** Whether an identity commitment has been revoked locally. */
  isRevoked(commitment: bigint): boolean {
    return this.slashing?.isRevoked(commitment) ?? false;
  }

  /**
   * Vouchers this node has issued.
   *
   * Each record holds only `(nullifier_issue, epoch, counter)` — by
   * design there is no recipient identifier, so this cannot reconstruct
   * the endorsement graph (RFC 003 §5.2).
   */
  getIssuanceRecords(): readonly IssuanceRecord[] {
    return this.voucherService?.listIssuanceRecords() ?? [];
  }

  /** Peers discovered on the local network via mDNS. */
  getDiscoveredPeers(): DiscoveredPeer[] {
    return this.discovery?.getPeers() ?? [];
  }

  /** Subscribe to mDNS peer discovery. */
  onPeerDiscovered(handler: (peer: DiscoveredPeer) => void): () => void {
    if (!this.discovery) return () => undefined;
    return this.discovery.onPeerDiscovered(handler);
  }

  // ─── Network state ────────────────────────────────────────────────────

  /** Whether the client currently considers itself online. */
  get isOnline(): boolean {
    return this.online;
  }

  /** Current network status snapshot. */
  getNetworkStatus(): NetworkStatus {
    return {
      // `connected` answers "can I deliver", so it counts paired peers
      // only — the same set publish() sends to. `peerCount` counts every
      // live connection including unpaired ones, which is what an app
      // needs to surface a stranger's request. They differ on purpose.
      connected: this.online && this.peers.listPairedConnected().length > 0,
      peerCount: this.peers.connectedCount,
      relayActive: false,
      lastSyncTimestamp: this.sessions.lastSync,
    };
  }

  /**
   * Simulate or record loss of connectivity.
   *
   * Messages sent while offline queue in the outbox instead of hitting
   * the wire.
   */
  goOffline(): void {
    if (!this.online) return;

    this.online = false;
    this.onNetworkStatus.emit('status', this.getNetworkStatus());
  }

  /**
   * Restore connectivity and flush anything queued while offline.
   *
   * @returns Number of outbox entries successfully delivered.
   */
  async goOnline(): Promise<number> {
    this.online = true;
    const result = await this.flushOutbox();
    this.onNetworkStatus.emit('status', this.getNetworkStatus());

    return result;
  }

  /**
   * Deliver every queued message, refreshing stale proof epochs.
   *
   * @returns Number of entries delivered.
   */
  async flushOutbox(): Promise<number> {
    const identity = this.requireIdentity();

    const { sent } = await this.outbox.flush(async (entry) => {
      // The message was already written to the CRDT when it was sent, so
      // replay its recorded timestamp and sequence rather than deriving
      // fresh ones — the peer must order it exactly as we do.
      const recorded =
        this.documents.getDocument(entry.channelId)?.messages?.[entry.id];

      await this.sessions.publish({
        id: entry.id,
        channelId: entry.channelId,
        authorDid: identity.did,
        content: entry.content,
        timestamp: recorded?.timestamp ?? Math.floor(entry.createdAt / 1000),
        messageIndex: recorded?.messageIndex ?? 0,
      });
    });

    return sent;
  }

  // ─── Persistence ──────────────────────────────────────────────────────

  /**
   * Checkpoint all CRDT documents to storage (RFC 002 §4.4).
   *
   * @returns Number of documents written, or 0 without storage.
   */
  checkpoint(): number {
    if (!this.documentStore) return 0;
    return this.documentStore.checkpointAll(this.documents);
  }

  /** The in-memory CRDT document set. */
  getDocuments(): DocumentManager {
    return this.documents;
  }

  /**
   * Get the current outbox queue size.
   */
  get outboxSize(): number {
    return this.outbox.size;
  }

  /**
   * Get the current client configuration.
   */
  getConfig(): Readonly<
    Required<Omit<ClientConfig, 'proofArtifacts'>> &
      Pick<ClientConfig, 'proofArtifacts'>
  > {
    return this.config;
  }

  /**
   * Disconnect from the network and clean up resources.
   * Flushes outbox, disconnects peers, resets worker pool.
   */
  async disconnect(): Promise<void> {
    // Persist merged state before tearing anything down. `checkpoint()`
    // only enqueues, so the flush is what actually gets it to disk —
    // closing storage first would discard every queued write.
    try {
      this.checkpoint();
      await this.documentStore?.flush();
      await this.voucherStore?.flush();
    } catch {
      // A persistence failure must not block shutdown.
    }

    if (this.discovery) {
      await this.discovery.stop();
      this.discovery = null;
    }
    if (this.transport) {
      await this.transport.close();
      this.transport = null;
    }
    if (this.storage) {
      await this.storage.close();
      this.storage = null;
      this.documentStore = null;
      this.messageStore = null;
    }

    this.peers.clear();
    this.online = false;
    this.onNetworkStatus.removeAllListeners();
    this.onPeerConnected.removeAllListeners();
  }

  // ─── Bootstrap ────────────────────────────────────────────────────────

  private async bootstrapInternalEngine(): Promise<void> {
    const storage = await initStorage(
      this.config.storagePath,
      this.outbox,
      this.runtime.storage,
    );
    this.storage = storage.driver;
    this.documentStore = storage.documents;
    this.messageStore = storage.messages;

    this.localIdentity = await initIdentity(
      this.identity,
      this.storage,
      // Empty means "not configured" — secrets stay in plaintext, which
      // is only acceptable in development.
      this.config.storageKey.length > 0 ? this.config.storageKey : undefined,
    );

    // Voluntary revocation is applied locally and never gossiped: a
    // USER_REVOKED tombstone carries no proof that its signer owns the
    // commitment it names, so peers reject it. Broadcasting one that
    // peers honour would let anyone revoke anyone (RFC 003 §7.1).
    this.identity.attachRevocationPublisher(async (tombstone) => {
      await this.slashing?.applyLocalRevocation(tombstone);
    });

    this.transport = await initTransport(
      this.requireIdentity(),
      this.runtime,
      (connection) => {
        this.sessions.registerConnection(connection);
        this.announcePeer(connection.peerDid, 'inbound');
        void this.drainAfterReconnect();
      },
    );

    this.discovery = await initDiscovery(this.requireIdentity(), this.runtime);

    this.wireProofService();
    this.wireChatService();
    this.wireSyncedMessages();
    await this.wireTrustService();
    this.wireGroupService();

    // Restore state persisted by a previous run.
    await this.documentStore.restoreAll(this.documents);
    await this.outbox.hydrate();
  }

  /**
   * Stand up the Groth16 prover when circuit artifacts are available.
   *
   * Construction is where a missing artifact surfaces, and it surfaces
   * at `init()` rather than on the first anonymous send — finding out
   * mid-conversation that proving was never possible is far worse than
   * failing to start.
   */
  private wireProofService(): void {
    // Stood up whenever the artifacts are present, not when the local
    // setting says so: a peer that joins a proof-required channel must
    // be able to prove and verify there regardless of what it would
    // have chosen for channels of its own.
    if (!this.config.proofArtifacts && resolveArtifacts() === null) return;

    this.proofs = new ProofService({
      artifacts: this.config.proofArtifacts,
      getIdentitySecret: () => this.requireIdentity().identitySecret,
      getMembershipTree: (channelId) => this.groups.getMembershipTree(channelId),
      allowDevelopmentCeremony: this.config.allowDevelopmentCeremony,
    });
  }

  /**
   * Surface messages that arrived by document sync rather than as an
   * envelope on `0x02`.
   *
   * `CrdtSyncEngine` reports which document a peer advanced; the chat
   * service works out which messages inside it are new. Without this the
   * `0x01` path merges silently and an application appending on
   * `onMessage` never learns, which is indistinguishable from loss.
   */
  private wireSyncedMessages(): void {
    this.syncEngine.onDocumentUpdate((update) => {
      // The handler is synchronous by contract, so this cannot be
      // awaited; a failure to emit must not disturb the sync loop.
      void this.chat.emitSynced(update.docId).catch(() => {});
    });
  }

  private wireChatService(): void {
    this.chat.attach({
      documents: this.documents,
      outbox: this.outbox,
      getLocalDid: () => this.requireIdentity().did,
      // Paired *and* connected. `connectedCount` includes strangers who
      // merely completed a handshake, and publish() sends to paired
      // peers only — so counting them reports reachability the send path
      // does not have, and a stranger's connection alone would suppress
      // the outbox.
      isOnline: () => this.online && this.peers.listPairedConnected().length > 0,
      publish: (payload) => this.sessions.publish(payload),
      // Relay every local change onward. Without this a message reaches
      // only peers this node is directly connected to, so a group in any
      // shape but a full mesh splits into partial conversations.
      onDocumentChanged: (channelId) => {
        void this.sessions.pushDocument(channelId).catch(() => {
          // A peer that cannot be reached now converges on reconnect;
          // failing to relay must not fail the local write.
        });
      },
      persist: async (message) => {
        await this.messageStore?.save(message);
      },
      createAnonymousSignal: async (channelId, messageIndex) => {
        const identity = this.requireIdentity();
        const epoch = currentEpoch();

        // The signal binds (secret, epoch, index): reusing an index
        // within an epoch is exactly what exposes the secret, which is
        // what makes anonymous rate limiting enforceable (RFC 003 §4.1).
        const signal = createSignal(
          identity.identitySecret,
          {
            version: 1,
            streamId: StreamType.E2EE_MESSAGE,
            epoch,
            tier: 0,
            ciphertextHash: sha256(
              new TextEncoder().encode(`${channelId}:${messageIndex}`),
            ),
            recipientId: 0n,
          },
          messageIndex,
        );

        this.lastAnonymousSignal = signal;

        // Policy comes from the channel's signed anchor, so every member
        // reaches the same answer. Deciding locally would let two
        // validly-configured peers partition: the stricter one drops
        // every message the laxer one sends, silently and with no error
        // on either side.
        let zkProof;
        if (this.groups.requiresProofs(channelId)) {
          if (!this.proofs) {
            throw new Error(
              `Channel ${channelId} requires Groth16 proofs but no circuit ` +
                'artifacts are available. Run `npm run zk:build` or pass ' +
                '`proofArtifacts` in ClientConfig.',
            );
          }
          zkProof = await this.proofs.prove(channelId, signal);
        }

        // The share travels with the message: slashing needs two points
        // on the same line, and without `y` on the wire a recipient can
        // see a reused nullifier but cannot interpolate the secret.
        return {
          nullifierHash: fieldToHex(signal.nullifier),
          share: { x: fieldToHex(signal.x), y: fieldToHex(signal.y) },
          zkProof,
        };
      },

      verifyRlnSignal: (payload) => this.verifyRlnSignal(payload),
    });
  }

  /** Attach group management (RFC 004 §7.3). */
  private wireGroupService(): void {
    const storage = this.storage;
    if (!storage) {
      throw new Error('Group service requires storage to be initialised first');
    }

    this.groups.attach({
      storage,
      documents: this.documents,
      getLocalDid: () => this.requireIdentity().did,
      getSigningKey: () => this.requireIdentity().signing,
      getCommitment: () => this.requireIdentity().commitment,
      saveAnchor: (anchor) => this.saveGenesisAnchor(anchor),
      loadAnchor: (channelId) => this.getGenesisAnchor(channelId),
      defaultRequireProofs: () => this.config.zkProofs === 'anonymous',
      announceMembership: (channelId) => {
        const frame = this.membershipSync.advertise(channelId);
        if (!frame) return;

        for (const peer of this.peers.listConnected()) {
          void peer.connection?.send(StreamType.CRDT_SYNC, frame);
        }
      },
      announceDeparture: (departure) => {
        // Broadcast the tombstone so peers stop counting us as a member.
        for (const frame of this.membershipSync.announceDeparture(departure)) {
          for (const peer of this.peers.listConnected()) {
            void peer.connection?.send(StreamType.CRDT_SYNC, frame);
          }
        }
      },
    });
  }

  /**
   * Validate an inbound anonymous message's RLN signal.
   *
   * Two checks, in order:
   *   1. The message index is inside the sender's rolling-window quota.
   *   2. The share is fed to the slashing detector, so a second message
   *      under the same nullifier reveals the sender's secret and
   *      triggers a revocation.
   *
   * The message is still admitted when detection fires — the sender is
   * revoked, but the message they already sent is not retroactively
   * rewritten. Rejecting it would give an attacker a way to un-send.
   *
   * ## Without a proof, this is advisory, not enforcement
   *
   * On a channel whose anchor does not require proofs, neither check is
   * binding. Nothing ties `nullifierHash` or `rlnShare` to the sender's
   * secret, so both are just field elements the sender chose: a fresh
   * nullifier per message never collides, never trips the detector, and
   * costs nothing to mint. `isWithinQuota` then bounds a number the
   * attacker also picked.
   *
   * What survives is real but narrow — it catches an *honest* client that
   * double-sends under one nullifier, and it makes accidental quota
   * breaches visible. It stops nobody who is trying.
   *
   * Cryptographic enforcement requires `requireProofs` on the channel
   * anchor, which makes the Groth16 verification below mandatory. Treat
   * proof-disabled RLN as bookkeeping and do not describe it to users as
   * spam protection.
   *
   * @returns False when the signal is missing, malformed, or over quota.
   */
  private async verifyRlnSignal(payload: MessagePayload): Promise<boolean> {
    if (payload.nullifierHash === undefined) return true;
    if (!payload.rlnShare) return false;

    // Tier 0 until reputation proofs are enabled; quota spans the
    // rolling window (RFC 003 §4.1).
    if (!isWithinQuota(payload.messageIndex, 0)) return false;

    let nullifier: bigint;
    let x: bigint;
    let y: bigint;
    try {
      nullifier = hexToField(payload.nullifierHash);
      x = hexToField(payload.rlnShare.x);
      y = hexToField(payload.rlnShare.y);
    } catch {
      return false;
    }

    // Same policy source as the send path. A channel that requires
    // proofs must reject a message carrying none — otherwise a sender
    // strips it and is indistinguishable from one who complied.
    if (this.groups.requiresProofs(payload.channelId)) {
      if (!this.proofs) return false;
      if (!payload.zkProof) return false;

      const ok = await this.proofs.verify(payload.channelId, payload.zkProof, {
        nullifier,
        x,
        y,
      });
      if (!ok) return false;
    }

    void this.slashing?.handleObservedShare({
      x,
      y,
      nullifier,
      epoch: currentEpoch(),
    });

    return true;
  }

  /** Assemble and attach the Web-of-Trust stack (RFC 003 §5, RFC 004 §6). */
  private async wireTrustService(): Promise<void> {
    if (!this.storage) {
      throw new Error('Trust service requires storage to be initialised first');
    }

    const stack = await createTrustStack({
      storage: this.storage,
      trust: this.trust,
      getIdentity: () => this.requireIdentity(),
      currentEpoch: () => currentEpoch(),
      ensureBlindKeypair: () => this.identity.ensureBlindKeypair(),
    });

    this.voucherService = stack.vouchers;
    this.voucherHandshake = stack.handshake;
    this.voucherStore = stack.voucherStore;

    this.slashing = createSlashingStack({
      getIdentity: () => this.requireIdentity(),
      connections: () =>
        this.peers
          .listConnected()
          .map((peer) => peer.connection!)
          .filter(Boolean),
      store: stack.store,
    });
  }

  /**
   * The live local identity.
   *
   * Read through to `IdentityService` rather than returning a cached
   * copy: `recoverFromMnemonic` replaces the identity in place, and a
   * stale cache would leave the client signing and encrypting with the
   * keys it was booted with.
   */
  private requireIdentity(): LocalIdentity {
    if (this.identity.hasIdentity) return this.identity.getLocalIdentity();

    if (!this.localIdentity) {
      throw new Error('Client identity is not initialised');
    }
    return this.localIdentity;
  }

  private requireTransport(): ITransport {
    if (!this.transport) {
      throw new Error('Client transport is not initialised');
    }
    return this.transport;
  }
}

/**
 * Fail fast when the platform has no Web Crypto.
 *
 * Browsers expose `crypto.getRandomValues` and `crypto.subtle` only in a
 * Secure Context — HTTPS or localhost. Served over plain HTTP,
 * `crypto.subtle` is simply `undefined`, and the first failure would
 * otherwise surface deep inside key generation as a confusing type
 * error, long after the real cause.
 *
 * Every key this SDK produces depends on these, so there is no degraded
 * mode worth offering.
 */
function assertCryptoAvailable(): void {
  // Typed structurally: the DOM lib is deliberately not in scope (see
  // `indexeddb-driver.ts`), so `Crypto` is not a known global name here.
  const webCrypto = (
    globalThis as {
      crypto?: { getRandomValues?: unknown; subtle?: unknown };
    }
  ).crypto;

  if (typeof webCrypto?.getRandomValues !== 'function') {
    throw new Error(
      'No Web Crypto available. In a browser this means the page is not a ' +
        'Secure Context — serve it over HTTPS or from localhost.',
    );
  }

  if (!webCrypto.subtle) {
    throw new Error(
      'crypto.subtle is unavailable. In a browser this means the page is ' +
        'not a Secure Context — serve it over HTTPS or from localhost. ' +
        'Identity keys cannot be generated without it.',
    );
  }
}
