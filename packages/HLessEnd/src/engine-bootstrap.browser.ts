/**
 * @dicsussion/sdk — Engine Assembly (BROWSER VARIANT)
 *
 * Identical to `engine-bootstrap.ts` except that `initStorage` requires an
 * injected driver instead of falling back to SQLite.
 *
 * ## Why a separate file rather than a `browser: false` mapping
 *
 * The Node variant imports `SQLiteDriver` statically. `sdk/browser` keeps
 * that class out of its *barrel*, but the barrel is not the only path to
 * it: `browser.js -> client.js -> engine-bootstrap.js` reaches the static
 * import regardless, so a browser bundle pulled in `better-sqlite3` no
 * matter which entry point was used.
 *
 * The `browser` field mapped the module to `false`, which yields an empty
 * module — and a *named* import against an empty module fails at
 * resolution, before the `typeof SQLiteDriver !== 'function'` guard below
 * could ever observe `undefined`. That guard was written against an
 * assumption that does not hold under strict ESM.
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
import type { WebSocketLike } from '@dicsussion/core/transport';
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

export interface TransportOptions {
  /**
   * Backend selection; defaults to the in-process transport.
   *
   * `'websocket'` routes through a relay and is the only backend a
   * browser can use — it requires `relayUrl`. Supplying an `ITransport`
   * instance is also allowed, but note it will carry whatever identity
   * it was built with rather than this client's.
   */
  readonly transport?: 'local' | 'iroh' | 'websocket' | ITransport;
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
  // No SQLite in a browser, and no static import of it in this file — so
  // the caller must supply a driver. `storagePath` is accepted for
  // signature parity with the Node variant and is unused here; IndexedDB
  // is named by database, not by filesystem path.
  if (!injectedDriver) {
    throw new Error(
      'No storage driver available. In a browser, pass ' +
        '`storage: new IndexedDbDriver()` — SQLite is a native module and ' +
        'is excluded from browser builds.',
    );
  }

  const driver = injectedDriver;
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
  if (typeof backend === 'object') {
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
