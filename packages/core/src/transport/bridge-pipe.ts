/**
 * @dicsussion/transport — Bridged transport host contract
 *
 * The seam that lets a non-Node host — Tauri, React Native, Electron —
 * supply the bytes while the SDK keeps the RFC 001 §5 handshake.
 *
 * **The contract is an ordered byte stream, nothing more.** A host may
 * split one `send` across several `onData` calls, or coalesce several
 * sends into one; both are correct. Message boundaries are *not* part of
 * the contract, because a host cannot preserve them without
 * reimplementing framing that the SDK already owns — and a boundary bug
 * would surface only mid-handshake, under load, on a real network.
 *
 * Ordering and integrity are assumed, since every channel a host would
 * bridge (a QUIC stream, a WebSocket, a TLS socket) already guarantees
 * them.
 */

/** Where to dial. Mirrors the dialable parts of a `PeerTicket`. */
export interface BridgeTarget {
  /**
   * The peer's 32-byte transport public key — its Iroh `EndpointId`.
   *
   * The host dials this, not the `did:key`: only the SDK can tie the two
   * together, and it does so during the handshake.
   */
  readonly transportKey: Uint8Array;
  /** Direct socket addresses to try, e.g. `"192.168.1.4:4242"`. */
  readonly directAddresses: readonly string[];
  /** Relay endpoint to fall back to when hole-punching fails. */
  readonly relayUrl?: string;
}

/** How this node is reachable, as only the host can know. */
export interface BridgeAddresses {
  /**
   * Socket addresses peers can try, e.g. `"203.0.113.4:41641"`.
   *
   * Discovery is not instant — a public address arrives from STUN some
   * time after the socket binds. Report what is known now; a ticket
   * published too early carries LAN addresses only and is undialable
   * from any other network.
   */
  readonly directAddresses: readonly string[];
  /** Relay endpoint to publish as a fallback, once one is assigned. */
  readonly relayUrl?: string;
}

/** What a host reports about a connection it did not initiate. */
export interface BridgeInbound {
  /**
   * The transport key the peer authenticated with, if the host knows it.
   *
   * Named for what is actually established. A QUIC/TLS handshake proves
   * ownership of a *transport* key, which says nothing about who owns the
   * `did:key` the protocol is built on — only the SDK handshake settles
   * that. A host physically cannot supply a truthful `did:key` here, so
   * it is not asked for one.
   */
  readonly unverifiedTransportId?: string;
}

/**
 * A bidirectional byte channel owned by the host.
 *
 * Connections are named by an opaque host-assigned id; the SDK never
 * interprets it. Ids may be recycled once a connection is finished —
 * `onInbound` is taken as announcing a new connection, and any state
 * held against that id is discarded — but two connections must never be
 * live under the same id at once.
 */
export interface BridgePipe {
  /**
   * How this node is currently reachable.
   *
   * The SDK derives the transport *key* from the identity, but only the
   * host knows the *addresses* behind it, so a dialable ticket cannot be
   * assembled without this.
   */
  addresses(): Promise<BridgeAddresses>;

  /**
   * Dial a peer.
   *
   * @returns The new connection's id.
   */
  connect(target: BridgeTarget): Promise<string>;

  /** Write bytes to a connection. Ordering must be preserved. */
  send(connectionId: string, bytes: Uint8Array): Promise<void>;

  /**
   * Bytes arrived. May be a partial message, several, or both.
   *
   * @returns Unsubscribe function.
   */
  onData(
    handler: (connectionId: string, bytes: Uint8Array) => void,
  ): () => void;

  /**
   * A peer dialled us and the host accepted the byte channel.
   *
   * @returns Unsubscribe function.
   */
  onInbound(
    handler: (connectionId: string, info: BridgeInbound) => void,
  ): () => void;

  /**
   * A connection went away, from either end.
   *
   * @returns Unsubscribe function.
   */
  onClosed(handler: (connectionId: string) => void): () => void;

  /** Tear down one connection. */
  disconnect(connectionId: string): Promise<void>;

  /** Tear down the host and every connection it holds. */
  close(): Promise<void>;
}
