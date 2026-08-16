/**
 * @dicsussion/sdk — Engine Assembly
 *
 * Builds the storage, identity and transport layers a client needs.
 *
 * Kept out of `DicsussionClient` so the facade stays an API surface
 * rather than an assembler (AGENT_INSTRUCTIONS §4.1 rule 3). Ordering
 * matters and is enforced here: storage first, because identity and the
 * outbox are restored from it; identity next, because the transport key
 * is derived from it.
 */

import { IrohTransport } from '@dicsussion/core/transport';
import { WebSocketTransport } from '@dicsussion/core/transport';
import type { Ed25519KeyPair, WebSocketLike } from '@dicsussion/core/transport';
import { LocalTransport } from '@dicsussion/core/transport';
import { MdnsDiscovery } from '@dicsussion/core/transport';
import type { IDatagramSocket } from '@dicsussion/core/transport';
import type {
  IConnection,
  ITransport,
} from '@dicsussion/core/transport';
import type { IdentityService, LocalIdentity } from './identity-service.js';
import type { OutboxManager } from './outbox.js';
import { DocumentStore } from './storage/document-store.js';
import { MessageStore } from './storage/message-store.js';
import { SQLiteDriver } from './storage/sqlite-driver.js';
import type { IStorageDriver } from './storage/types.js';

/** Storage handles produced during bootstrap. */
export interface StorageLayer {
  /**
   * The active driver, as the interface rather than the SQLite class.
   *
   * Widening this is what lets a caller supply IndexedDB — pinning the
   * concrete type here would have kept `better-sqlite3` on the required
   * path for every runtime, webviews included.
   */
  readonly driver: IStorageDriver;
  readonly documents: DocumentStore;
  readonly messages: MessageStore;
}

/**
 * Build a transport once the local identity exists.
 *
 * Transports authenticate as the node, so they need its Ed25519 keypair
 * — but that is derived during bootstrap from a seed the caller never
 * holds, which makes a ready-made instance impossible to supply for any
 * transport that needs one. The client therefore calls this with the
 * derived identity and uses whatever it returns.
 *
 * The natural use is a non-Node host bridging its own socket:
 *
 * ```ts
 * transport: (identity) => createBridgedTransport(pipe, { identity })
 * ```
 *
 * @param identity This node's Ed25519 keypair. The transport public key
 *   published in tickets is derived from it, so a transport that mints
 *   its own would advertise an address no peer could dial.
 */
export type TransportFactory = (
  identity: Ed25519KeyPair,
) => ITransport | Promise<ITransport>;

export interface TransportOptions {
  /**
   * Backend selection; defaults to the in-process transport.
   *
   * `'websocket'` routes through a relay and is the only backend a
   * browser can use — it requires `relayUrl`. Supplying an `ITransport`
   * instance is also allowed, but note it will carry whatever identity
   * it was built with rather than this client's.
   */
  readonly transport?:
    | 'local'
    | 'iroh'
    | 'websocket'
    | ITransport
    | TransportFactory;
  readonly bindAddr?: string;
  readonly localOnly?: boolean;
  /** Relay endpoint for the `'websocket'` backend. */
  readonly relayUrl?: string;
  /** Socket factory for the `'websocket'` backend; defaults to the global. */
  readonly createSocket?: (url: string) => WebSocketLike;
}

export interface DiscoveryOptions {
  readonly enableDiscovery?: boolean;
  readonly discoveryPort?: number;
  readonly discoverySocket?: IDatagramSocket;
  readonly beaconIntervalMs?: number;
}

/**
 * Open local storage and attach it to the outbox.
 *
 * @param storagePath SQLite path, or `:memory:`. Ignored when a driver
 *   is injected.
 * @param outbox Outbox to back with the same driver.
 * @param injectedDriver Storage backend to use instead of SQLite —
 *   `IndexedDbDriver` in a browser, or a test double. It is initialised
 *   here, so callers hand over an unopened instance.
 */
export async function initStorage(
  storagePath: string,
  outbox: OutboxManager,
  injectedDriver?: IStorageDriver,
): Promise<StorageLayer> {
  // `SQLiteDriver` is mapped out of browser bundles (package.json
  // `browser` field), so in a webview this is undefined rather than a
  // constructor. Saying so plainly beats `SQLiteDriver is not a
  // constructor`, which sends people looking in the wrong place.
  if (!injectedDriver && typeof SQLiteDriver !== 'function') {
    throw new Error(
      'No storage driver available. In a browser, pass ' +
        '`storage: new IndexedDbDriver()` — SQLite is a native module and ' +
        'is excluded from browser builds.',
    );
  }

  const driver = injectedDriver ?? new SQLiteDriver(storagePath);
  await driver.initialize();

  outbox.attachStorage(driver);

  return {
    driver,
    documents: new DocumentStore(driver),
    messages: new MessageStore(driver),
  };
}

/**
 * Load the persisted identity, or create one on first run.
 *
 * @param identity The identity service to hydrate.
 * @param storage Driver to persist to, when available.
 */
export async function initIdentity(
  identity: IdentityService,
  storage: IStorageDriver | null,
  storageKey?: Uint8Array | string,
): Promise<LocalIdentity> {
  // Must precede `loadOrCreate`, or a first-run identity would be
  // written in plaintext before the key is known.
  if (storageKey !== undefined) identity.attachStorageKey(storageKey);
  if (storage) identity.attachStorage(storage);

  await identity.loadOrCreate();
  return identity.getLocalIdentity();
}

/**
 * Build the configured transport backend.
 *
 * Defaults to `local` so the test suite stays fast and never requires
 * the native Iroh module — `IrohTransport` imports it dynamically, so
 * choosing `local` never touches the native binding at all.
 *
 * @param identity Local identity; the transport key is derived from it.
 * @param options Backend selection and binding.
 * @param onConnection Handler for inbound connections.
 */
export async function initTransport(
  identity: LocalIdentity,
  options: TransportOptions,
  onConnection: (connection: IConnection) => void,
): Promise<ITransport> {
  const backend = options.transport ?? 'local';

  let transport: ITransport;
  if (typeof backend === 'function') {
    // The identity is derived here, during bootstrap, from a seed the
    // caller never sees — so a transport that needs it cannot be built
    // before this point. Hence a factory rather than an instance.
    transport = await backend(identity.signing);
  } else if (typeof backend === 'object') {
    transport = backend;
  } else if (backend === 'websocket') {
    if (!options.relayUrl) {
      throw new Error(
        "The 'websocket' transport needs a relayUrl: a browser peer is only " +
          'reachable through a relay.',
      );
    }

    const ws = new WebSocketTransport({
      relayUrl: options.relayUrl,
      identity: identity.signing,
      createSocket: options.createSocket,
    });
    await ws.start();
    transport = ws;
  } else if (backend === 'iroh') {
    transport = await IrohTransport.create({
      identity: identity.signing,
      bindAddr: options.bindAddr,
      localOnly: options.localOnly,
    });
  } else {
    transport = new LocalTransport(identity.signing);
  }

  transport.onConnection(onConnection);
  return transport;
}

/**
 * Start mDNS beaconing, if enabled.
 *
 * @returns The running discovery service, or null when disabled.
 */
export async function initDiscovery(
  identity: LocalIdentity,
  options: DiscoveryOptions,
): Promise<MdnsDiscovery | null> {
  if (!options.enableDiscovery) return null;

  const discovery = new MdnsDiscovery({
    didKey: identity.did,
    port: options.discoveryPort ?? 4242,
    socket: options.discoverySocket,
    beaconIntervalMs: options.beaconIntervalMs,
  });

  await discovery.start();
  return discovery;
}
