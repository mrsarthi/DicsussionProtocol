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

import { EventEmitter } from 'node:events';

import { DocumentManager } from '../../core/src/crdt/document-manager.js';
import { CrdtSyncEngine } from '../../core/src/crdt/sync-engine.js';
import { LocalTransport } from '../../core/src/transport/local-transport.js';
import { MdnsDiscovery } from '../../core/src/transport/mdns-discovery.js';
import type { IDatagramSocket } from '../../core/src/transport/datagram-socket.js';
import type { DiscoveredPeer } from '../../core/src/transport/mdns-discovery.js';
import type { IConnection } from '../../core/src/transport/transport-interface.js';
import type { PeerTicket } from '../../core/src/transport/types.js';
import { ChatService } from './chat-service.js';
import { GroupService } from './group-service.js';
import { IdentityService } from './identity-service.js';
import type { LocalIdentity } from './identity-service.js';
import { OutboxManager } from './outbox.js';
import { PeerRegistry } from './peer-registry.js';
import { SessionManager } from './session-manager.js';
import { DocumentStore } from './storage/document-store.js';
import { MessageStore } from './storage/message-store.js';
import { SQLiteDriver } from './storage/sqlite-driver.js';
import { TrustService } from './trust-service.js';
import type { ClientConfig, NetworkStatus } from './types.js';

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
  public readonly onNetworkStatus = new EventEmitter<{ status: [NetworkStatus] }>();

  private readonly outbox: OutboxManager;
  private readonly config: Required<ClientConfig>;
  private readonly runtime: ClientRuntimeOptions;
  private readonly documents = new DocumentManager();
  private readonly peers = new PeerRegistry();
  private readonly syncEngine: CrdtSyncEngine;
  private readonly sessions: SessionManager;

  private storage: SQLiteDriver | null = null;
  private documentStore: DocumentStore | null = null;
  private messageStore: MessageStore | null = null;
  private transport: LocalTransport | null = null;
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
    };
    this.runtime = runtime;

    this.chat = new ChatService();
    this.groups = new GroupService();
    this.trust = new TrustService();
    this.identity = new IdentityService();
    this.outbox = new OutboxManager(this.config.maxOutboxSize);
    this.syncEngine = new CrdtSyncEngine(this.documents);
    this.sessions = new SessionManager({
      peers: this.peers,
      syncEngine: this.syncEngine,
      getEncryptionSecret: () => this.requireIdentity().encryption.secretKey,
      onMessage: async (payload) => {
        await this.chat.ingestRemote(payload);
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

  /** A connection ticket other peers can dial (RFC 001 §3.3). */
  getTicket(): PeerTicket {
    const identity = this.requireIdentity();
    return {
      didKey: identity.did,
      nodeId: identity.signing.publicKey,
      directAddresses: [],
      derpRelay: this.config.relayEndpoints[0],
    };
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

    if (!this.peers.getPeer(ticket.didKey)) {
      throw new Error(
        `Unknown peer ${ticket.didKey}. Call addPeer() with their X25519 key first.`,
      );
    }

    const connection = await transport.connect(ticket);
    this.sessions.registerConnection(connection);
    await this.sessions.beginSync(connection);

    return connection;
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
      connected: this.online && this.peers.connectedCount > 0,
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
      const recorded = this.documents.getDocument(entry.channelId)?.messages?.[entry.id];

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
   * Checkpoint all CRDT documents to SQLite (RFC 002 §4.4).
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
  getConfig(): Readonly<Required<ClientConfig>> {
    return this.config;
  }

  /**
   * Disconnect from the network and clean up resources.
   * Flushes outbox, disconnects peers, resets worker pool.
   */
  async disconnect(): Promise<void> {
    // Persist merged state before tearing anything down.
    try {
      this.checkpoint();
    } catch {
      // A checkpoint failure must not block shutdown.
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
  }

  // ─── Bootstrap ────────────────────────────────────────────────────────

  private async bootstrapInternalEngine(): Promise<void> {
    await this.initStorage();
    await this.initIdentity();
    await this.initTransport();
    await this.initDiscovery();

    this.wireChatService();

    // Restore state persisted by a previous run.
    this.documentStore?.restoreAll(this.documents);
    await this.outbox.hydrate();
  }

  private async initStorage(): Promise<void> {
    const driver = new SQLiteDriver(this.config.storagePath);
    await driver.initialize();

    this.storage = driver;
    this.documentStore = new DocumentStore(driver.getDatabase());
    this.messageStore = new MessageStore(driver);
    this.outbox.attachStorage(driver);
  }

  private async initIdentity(): Promise<void> {
    if (this.storage) this.identity.attachStorage(this.storage);
    await this.identity.loadOrCreate();
    this.localIdentity = this.identity.getLocalIdentity();
  }

  private async initTransport(): Promise<void> {
    const identity = this.requireIdentity();
    this.transport = new LocalTransport(identity.signing);

    // Accept inbound connections from peers dialling us.
    this.transport.onConnection((connection) => {
      this.sessions.registerConnection(connection);
    });
  }

  private async initDiscovery(): Promise<void> {
    if (!this.runtime.enableDiscovery) return;

    const identity = this.requireIdentity();
    this.discovery = new MdnsDiscovery({
      didKey: identity.did,
      port: this.runtime.discoveryPort ?? 4242,
      socket: this.runtime.discoverySocket,
      beaconIntervalMs: this.runtime.beaconIntervalMs,
    });

    await this.discovery.start();
  }

  private wireChatService(): void {
    this.chat.attach({
      documents: this.documents,
      outbox: this.outbox,
      getLocalDid: () => this.requireIdentity().did,
      isOnline: () => this.online && this.peers.connectedCount > 0,
      publish: (payload) => this.sessions.publish(payload),
      persist: async (message) => {
        await this.messageStore?.save(message);
      },
    });
  }

  private requireIdentity(): LocalIdentity {
    if (!this.localIdentity) {
      throw new Error('Client identity is not initialised');
    }
    return this.localIdentity;
  }

  private requireTransport(): LocalTransport {
    if (!this.transport) {
      throw new Error('Client transport is not initialised');
    }
    return this.transport;
  }
}
