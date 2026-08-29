# RFC 004: Headless Backend Engine, Web-of-Trust Storage & Client SDK

- **Target Module:** `@dicsussion/sdk` (`packages/HLessEnd`)
- **Status:** Draft
- **Author:** Parth
- **Last Updated:** 2026-08-27

---

## 1. Overview

This specification defines the Headless Backend Engine and Client SDK (`@dicsussion/sdk`) that acts as the primary orchestrator facade for the Dicsussion application. It encapsulates local persistence in SQLite or IndexedDB, local Web-of-Trust (WoT) score calculations, and a worker pool for the ZekPoc (Zero Knowledge Proof of Chat) cryptographic protocol.

The SDK is **host-agnostic**. It runs in Node, in a webview paired with a native layer, and in a browser, and it MUST NOT assume any particular process model. Earlier revisions of this document specified Electron IPC; that was never implemented and the requirement is withdrawn.

Application frontends import this SDK as a single library to access chat, group, identity, and zero-knowledge reputation features without directly managing low-level graph sockets or process executions.

---

## 2. Non-Goals

* **UI & Framework Rendering:** Providing React components, DOM elements, CSS styles, or platform-specific UI widgets.
* **Low-Level Wire Protocols:** Defining raw binary frame headers or network socket drivers.

---

## 3. Runtime Architecture & Process Isolation

To keep a UI responsive, the SDK MUST keep heavy cryptographic work off whatever thread renders it. How that separation is achieved is the host's concern — worker threads in Node, Web Workers in a browser, a native layer under a webview — and the SDK MUST work under all of them without naming one.

### 3.1 Multi-Process Execution Topology

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      APPLICATION / UI                                  │
│           Dicsussion Frontend  <--->  DicsussionClient Facade          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ in-process calls
┌───────────────────────────────────▼────────────────────────────────────┐
│                    HEADLESS ENGINE (@dicsussion/sdk)                   │
│  • Session management and frame routing                                │
│  • Local Web-of-Trust score calculator                                 │
│  • Outbox, CRDT sync, identity lifecycle                               │
└───────┬────────────────────────────┬───────────────────────┬───────────┘
        │  storage seam              │  transport seam       │
        ▼                            ▼                       ▼
┌──────────────────┐   ┌──────────────────────────┐  ┌──────────────────┐
│ IStorageDriver   │   │ ITransport               │  │ WORKER POOL      │
│ • SQLite (Node)  │   │ • Direct QUIC (Iroh)     │  │ • Proof gen      │
│ • IndexedDB      │   │ • Bridged host pipe      │  │ • Timeout-safe   │
│   (browser /     │   │ • Relayed WebSocket      │  │ • Crash recovery │
│    webview)      │   │ • In-process (tests)     │  │                  │
└──────────────────┘   └──────────────────────────┘  └──────────────────┘
```

**The two seams are what make the engine host-agnostic**, and both are
required. `better-sqlite3` is a native module that cannot load in a
webview, and a webview cannot open a QUIC socket — so a host that fits
neither default MUST be able to substitute both. See §7.1.

---

## 4. Local Persistence & State Storage

The SDK utilizes **SQLite** for desktop contexts and **IndexedDB** for browser contexts as the local-first persistence layer. Nodes persist state locally and synchronize Automerge deltas directly over Iroh QUIC streams.

### 4.1 Storage Layout

The local store is partitioned into logical collections:

1. **`identity`**: Holds local keypairs (Ed25519, X25519), ZekPoc identity secrets, and encrypted mnemonic backups.

   **Whenever the store is a real file rather than memory, an
   implementation MUST require a `storageKey` and MUST refuse to write
   secret key material without one.** A local-first design puts the
   entire identity on disk, so an unprotected store hands over the
   `did:key`, the X25519 key, and the RLN identity secret $a_0$ together.
   Where the key comes from is the application's concern — an OS keychain,
   a user passphrase, a hardware token — but its absence MUST be surfaced
   loudly rather than defaulted through.
2. **`wot_peers`**: Maps peer `did:key` identifiers to interaction counters, verified chat histories, and computed subjective trust scores.
3. **`voucher_redeemed`**: Tracks blind endorsement voucher tokens (`+5 POC` gifts) and redemption nullifiers to prevent double-spending.
4. **`channel_meta`**: Stores metadata, peer lists, and access control thresholds for active chat channels.
5. **`message_stream`**: Stores end-to-end encrypted message payloads and their proof metadata.
6. **`peer_profiles`**: One row per peer holding their self-published name,
   bio and picture (RFC 001 §6.2), including this node's own. Replaced on
   update rather than appended, so a profile has one current value and no
   history.
7. **`blobs`**: Content-addressed attachment bytes, keyed by SHA-256
   (RFC 001 §6.3). A row whose `received` is below its `size` is an
   unfinished transfer that a later request resumes from rather than
   restarting.

---

## 5. ZekPoc Cryptographic Web Worker Pool

Because ZekPoc zero-knowledge proofs require significant processing power, the SDK offloads cryptographic proof generation and verification to a persistent Web Worker pool inside dedicated background processes.

### 5.1 Worker Bridge Interface

```typescript
export interface ZekPocProofInput {
  identitySecret: string;
  userScore: number;
  tierThreshold: number;
  epoch: number;
  messageIndex: number;
  stateRoot?: string;
}

export interface ZekPocProofOutput {
  proofHex: string;
  publicSignals: string[];
  nullifier: string;
  proofEpoch: number;
  stateRoot: string;
}

export interface IZekPocBinding {
  generateRangeProof(input: ZekPocProofInput, options?: { timeoutMs?: number }): Promise<ZekPocProofOutput>;
  verifyProof(proof: ZekPocProofOutput, options?: { timeoutMs?: number }): Promise<boolean>;
  isHealthy(): boolean;
  reset(): Promise<void>;
}
```

---

## 6. Local Web-of-Trust (WoT) Engine

The WoT engine calculates subjective peer trust scores entirely locally without querying central servers or exposing raw balances to the network.

### 6.1 Subjective Score Calculation Formula

The local score $S(P)$ for peer $P$ is calculated as:

$$S(P) = S_{\text{base}} + (10 \cdot C_{\text{verified}}) + (5 \cdot V_{\text{valid}}) - (2 \cdot I_{\text{issued}})$$

Where:
* $S_{\text{base}} = 0$ (Default baseline score for unverified contacts).
* $C_{\text{verified}}$ = Number of verified bidirectional chat sessions completed ($+10$ points each).
* $V_{\text{valid}}$ = Number of unblinded $+5$ Endorsement Vouchers redeemed ($+5$ points each).
* $I_{\text{issued}}$ = Number of endorsement vouchers issued by peer $P$ (deducting $2$ POC per issued voucher to prevent voucher farming).

Identities that produce double-spending RLN nullifiers are immediately blacklisted locally ($S(P) \to -\infty$), and their revoked status is gossiped across the network via Revocation Tombstones on sub-stream `0x03`.

### 6.2 Definition of a Verified Bidirectional Chat Session
A `verified bidirectional chat session` is a session that satisfies all of the following conditions:
1. The session contains at least one message from each participant.
2. Both participants produced valid ZK-RLN proofs for at least one message in that session.
3. The session spans at least $N$ distinct epochs, where $N = 3$ is the default minimum and the elapsed time MUST be at least 30 seconds.
4. The two participants are distinct identities; self-chats do not count.
5. Each peer counts at most one verified session for a given `did:key` per 24-hour window.

Only sessions that satisfy this definition contribute to $C_{\text{verified}}$.

---

## 7. Public Client SDK Surface (`DicsussionClient`)

The developer interface exposed by `@dicsussion/sdk` hides complex IPC calls and worker execution behind clean TypeScript namespaces.

### 7.1 SDK Initialization & Main Facade

```typescript
export interface ClientConfig {
  storagePath?: string;
  relayEndpoints?: string[];
  proofBackend?: 'wasm' | 'browser';
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  proofTimeoutMs?: number;
  autoReconnect?: boolean;
  maxOutboxSize?: number;
  /** Encrypts secret key material at rest. REQUIRED when storagePath
   *  names a real file — see §4.1. */
  storageKey?: string;
  /** Whether anonymous sends carry ZK proofs. Defaults to 'off'. */
  zkProofs?: 'off' | 'on';
  proofArtifacts?: {
    wasmPath: string;
    zkeyPath: string;
    verificationKeyPath: string;
  };
}

/**
 * Host substitutions. Separate from ClientConfig because these are
 * embedding seams, not user-facing settings.
 */
export interface ClientRuntimeOptions {
  transport?: 'local' | 'iroh' | 'websocket' | ITransport | TransportFactory;
  storage?: IStorageDriver;
  relayUrl?: string;
  bindAddr?: string;
  enableDiscovery?: boolean;
}

/**
 * Builds a transport once the identity exists.
 *
 * A transport authenticates as the node, so it needs the Ed25519
 * keypair — but that is derived during init() from a seed the caller
 * never holds. A ready-made instance is therefore impossible to supply
 * for any transport that authenticates, which is all of them.
 */
export type TransportFactory = (
  identity: Ed25519KeyPair,
) => ITransport | Promise<ITransport>;

export interface NetworkStatus {
  connected: boolean;
  peerCount: number;
  relayActive: boolean;
  lastSyncTimestamp: number;
}

/** A peer completed the §5 handshake, paired or not. */
export interface PeerConnectedEvent {
  peerDid: string;
  paired: boolean;
  direction: 'outbound' | 'inbound';
}

export class DicsussionClient {
  public readonly chat: ChatService;
  public readonly groups: GroupService;
  public readonly trust: TrustService;
  public readonly identity: IdentityService;
  public readonly blobs: BlobService;
  public readonly onNetworkStatus: Emitter<NetworkStatus>;
  public readonly onPeerConnected: Emitter<PeerConnectedEvent>;
  /**
   * A connection ended, from either side.
   *
   * The counterpart to `onPeerConnected`. Presence derived from the
   * connected event alone switches on and never off, and would report a
   * peer who closed their app hours ago as present.
   */
  public readonly onPeerDisconnected: Emitter<PeerDisconnectedEvent>;
  /**
   * A stranger asked to be paired (RFC 001 §6.4).
   *
   * Carries their ticket, bound to the did:key the handshake proved, and
   * a display name that is a claim rather than an identity.
   */
  public readonly onPairingRequest: Emitter<PairingRequest>;

  /** Ask a connected peer to pair, sending our own ticket. */
  requestPairing(
    peerDid: string,
    options?: { displayName?: string },
  ): Promise<boolean>;

  /** Requests received this session and not yet acted on. */
  pendingPairingRequests(): readonly PairingRequest[];

  /** Register the requester as a peer, using the ticket they sent. */
  acceptPairingRequest(request: PairingRequest): void;

  /** Discard a request without pairing. */
  declinePairingRequest(request: PairingRequest): void;

  public static async init(
    config?: ClientConfig,
    runtime?: ClientRuntimeOptions,
  ): Promise<DicsussionClient>;

  /** Register a peer's X25519 key, learned out of band. */
  addPeer(did: string, encryptionKey: Uint8Array): void;

  /**
   * Declare a conversation and who belongs to it.
   *
   * Separate from `addPeer` on purpose: pairing authorises a peer,
   * membership authorises a conversation. See §7.4.
   */
  chat.createChannel(channelId: string, participants?: readonly string[]): void;
  connect(ticket: PeerTicket): Promise<IConnection>;
  getTicket(): PeerTicket;
  getNetworkStatus(): NetworkStatus;
  disconnect(): Promise<void>;
}
```

**Pairing is not authorization derived from the wire.** `addPeer` is the
only thing that authorizes traffic. `connect` registers the key carried
in a ticket, but on the dialling side alone — the accepting side MUST
pair separately, or it will drop everything the dialer sends (RFC 001
§3.3). `onPeerConnected` exists so an application can surface an unpaired
peer's handshake rather than discard it silently; `paired` is the field
that decides what to do.

**`onPeerConnected` is not a delivery signal.** It reports that a
handshake completed, which says only that the far side holds the secret
behind the `did:key` it asserted.

### 7.2 Core Service API Signatures

#### `client.chat` Namespace
```typescript
export interface SendMessageOptions {
  channelId: string;
  content: string;
}

export interface ChatMessage {
  id: string;
  channelId: string;
  authorDid?: string;
  nullifierHash?: string;
  content: string;
  timestamp: number;
  verifiedTier: number;
  proofEpoch: number;
  proofValid: boolean;
  envelopeRef: string;
  zkProof?: string;
}

export class ChatService {
  static readonly MAX_LISTENERS_PER_CHANNEL = 64;

  async sendMessage(options: SendMessageOptions): Promise<ChatMessage> {
    // Sends content over Iroh QUIC streams with attached ZekPoc proof; if the peer is offline, the message is queued in the outbox until the next reconnect
    return {} as ChatMessage;
  }

  async getHistory(channelId: string, limit?: number): Promise<ChatMessage[]> {
    return [];
  }

  onMessage(channelId: string, callback: (msg: ChatMessage) => void): () => void {
    return () => {};
  }

  removeAllListeners(channelId: string): void {
    // Removes all listeners for a channel and clears any pending channel-scoped subscriptions.
  }

  /**
   * Send a signal that is only true while both peers are connected
   * (Sub-Stream `0x07`).
   *
   * Deliberately none of `sendMessage`'s guarantees: not written to the
   * document, not queued in the outbox, not retried, and not replayed to
   * a peer that reconnects. Returns how many peers received it, where
   * zero means nobody was connected rather than that anything failed.
   */
  async sendEphemeral(channelId: string, payload: Uint8Array): Promise<number> {
    return 0;
  }

  onEphemeral(
    channelId: string,
    callback: (fromDid: string, payload: Uint8Array) => void,
  ): () => void {
    return () => {};
  }
}
```

`SendMessageOptions.attachments` carries `BlobRef` handles (RFC 001
§6.3). Only the handles travel with the message; an implementation MUST
NOT send the bytes until a recipient requests them.

`SendMessageOptions.replyTo` and `ChatMessage.replyTo` carry the ids of
messages a message answers, as `readonly string[]`. They MUST be a
distinct field: encoded inside `content` a reference becomes a convention
every implementation must know forever, appears as literal text in any
that does not, and cannot be told apart from text the author wrote.

Ids are carried opaquely. An implementation MUST NOT drop a reference
that names a message it does not hold — replies arrive out of order, and
a peer may answer something predating this device's membership — and MUST
NOT reject the message on that basis. Resolution belongs to the
application. Both the count of references and their length MUST be
bounded, since they arrive from a peer and are written into the
conversation document (RFC 002 §3.1).

#### `client.trust` Namespace
```typescript
export interface PeerTrustProfile {
  did: string;
  subjectiveScore: number;
  tier: number;
  isBlacklisted: boolean;
}

export class TrustService {
  async getProfile(peerDid: string): Promise<PeerTrustProfile> {
    return {} as PeerTrustProfile;
  }

  async giftEndorsement(recipientDid: string): Promise<void> {
    // Generates a blinded voucher signature for +5 POC
  }
}
```

### 7.3 Group & Identity Service APIs
The SDK surface MUST expose concrete service definitions for group management and identity lifecycle operations so the client can create, recover, and rotate identities without reaching into undocumented internals.

Identity recovery is **implemented**, not aspirational: `exportMnemonic`
and `recoverFromMnemonic` restore the same `did:key` and the same
`cm_identity`, so channel membership survives a replaced device. The RSA
blind-signing key is *not* derived from the seed and is regenerated on
recovery, so peers MUST re-pair before endorsements can be issued again.

```typescript
export class GroupService {
  async createGroup(name: string, members: string[]): Promise<GroupInfo> {
    return {} as GroupInfo;
  }
  async joinGroup(groupId: string): Promise<void> {}
  async leaveGroup(groupId: string): Promise<void> {}
  async getGroupInfo(groupId: string): Promise<GroupInfo> {
    return {} as GroupInfo;
  }
  onInvite(callback: (invite: GroupInvite) => void): () => void {
    return () => {};
  }
}

export class IdentityService {
  async createIdentity(): Promise<Identity> {
    return {} as Identity;
  }
  async exportMnemonic(): Promise<string> {
    return '';
  }
  async recoverFromMnemonic(mnemonic: string): Promise<Identity> {
    return {} as Identity;
  }
  async getCurrentDid(): Promise<string> {
    return '';
  }
  async revokeKey(): Promise<void> {}

  /**
   * Publish a name, bio or picture (Sub-Stream `0x08`).
   *
   * Omitted fields are kept; `null` clears one. Reaches paired peers
   * that are connected now and the rest when they next connect.
   */
  async setMyProfile(update: ProfileUpdate): Promise<number> {
    return 0;
  }
  getMyProfile(): PeerProfile | undefined {
    return undefined;
  }
  getPeerProfile(did: string): PeerProfile | undefined {
    return undefined;
  }
  onPeerProfile(
    callback: (did: string, profile: PeerProfile) => void,
  ): () => void {
    return () => {};
  }
}
```

The display name in a profile is what a peer calls **themselves**, which
is not necessarily what an application should display. An implementation
holding a locally-assigned name SHOULD prefer it, so that changing one's
own name cannot change what appears in someone else's contact list.

#### `client.blobs` Namespace
```typescript
export interface BlobRef {
  /** Lowercase hex SHA-256 of the content. */
  hash: string;
  size: number;
  mime: string;
}

export class BlobService {
  /** Store bytes locally and return a handle. Nothing is sent. */
  async put(bytes: Uint8Array, mime: string): Promise<BlobRef> {
    return {} as BlobRef;
  }
  /** Fetch from local storage, or from any paired peer that has it. */
  async get(ref: BlobRef): Promise<Uint8Array> {
    return new Uint8Array();
  }
  async has(ref: BlobRef): Promise<boolean> {
    return false;
  }
  async delete(ref: BlobRef): Promise<void> {}
  onProgress(
    ref: BlobRef,
    callback: (received: number, total: number) => void,
  ): () => void {
    return () => {};
  }
}
```

Failures MUST be distinguishable: `BlobTooLargeError`,
`BlobUnavailableError` and `BlobCorruptError` are three different things
to tell a user, and an implementation that collapses them leaves an
application unable to say which happened.

An implementation MUST NOT pair automatically on receiving a request.
Acceptance is a judgement about which person a `did:key` belongs to, made
on a self-asserted name, and nothing in the protocol can make it for the
user. `pendingPairingRequests()` exists because a request may arrive
before the application subscribes and a peer sends at most one.

### 7.4 Conversation Membership

**A conversation carries its own participant list, and it is an
authorization boundary.** Messages are transmitted only to peers named in
it, and RFC 002 §3.3 requires the same of synchronisation. A conversation
naming nobody reaches nobody.

An implementation MUST NOT infer membership. Pairing cannot supply it —
being a contact says nothing about which conversations a peer belongs to
— and defaulting to "everyone currently paired" reproduces exactly the
disclosure the list exists to prevent, as soon as a user has two
contacts. Only the application knows that a chat opened from a given
contact is for that contact, so the application declares it:

```typescript
client.chat.createChannel(channelId, [theirDid]);
// or, on the first message that creates the channel:
client.chat.sendMessage({ channelId, content, participants: [theirDid] });
```

The local node is always a participant. A peer paired *later* is admitted
by an explicit call rather than as a side effect of pairing.

**Declaring a conversation MUST be authoritative, not additive.** Anyone
recorded and not named MUST be removed, and a separate operation MUST
exist for admitting someone to a conversation that already exists.

This is a security requirement rather than an ergonomic preference.
Channel identifiers are chosen by applications and travel in the clear;
they are identifiers, not secrets. A conversation may also come into
existence from an inbound message, and doing so records its sender — so
under additive semantics a peer could name the identifier of a
conversation it had no part in, be recorded as a participant, and receive
everything sent there afterwards, including messages the sender believed
were private to a third party. Authoritative declaration is what makes
naming a conversation decide who is in it.

**Inference of membership MUST be confined to the creation of a
conversation in response to an inbound message**, where it records that
message's author so a reply has somewhere to go. An implementation MUST
NOT infer membership on a conversation it already holds.

**Consequences an implementation MUST accept.** A send to an undeclared
channel succeeds locally, is recorded in history, queues in the outbox,
and is delivered to nobody. This is preferable to the alternative:
undeclared membership that defaults to sharing is a silent disclosure,
whereas undeclared membership that defaults to refusing is a visible
absence of delivery.

A group is a conversation with more than two participants. No separate
group type exists for ordinary chat.

#### Removal

An implementation MUST provide a way to remove a participant, and the
removal MUST apply in both directions: the peer is no longer sent
messages, no longer offered the document, **and their own messages and
document pushes are refused**.

The inbound half is the one that cannot be achieved above the protocol.
CRDT changes are not individually authenticated, so a peer who remains a
participant can write into a shared document however an application feels
about them — a local block suppresses display, not authorship.

Inbound checks MUST distinguish *"not a participant"* from *"this node
has no such conversation"*. A conversation absent locally has no
participant list, so an unconditional check refuses the first message of
every new conversation a paired peer starts. An unknown channel from a
paired peer is a new conversation; a known channel means its list is
authoritative.

**Removal is not retroactive and MUST NOT be presented as though it
were.** Whatever the peer already received is on their device. No
messaging protocol can reach into another party's storage, and an
interface implying otherwise misleads the user about what was achieved.

---

### 7.5 Offline Queue & Listener Safety
The backend MUST define an offline outbox queue for pending messages and reconnect state. Each outbox entry SHOULD include status and timestamps so stale proofs can be re-generated when the client reconnects. In addition, `ChatService.onMessage()` MUST enforce a per-channel listener cap and clean up listeners when channels are destroyed.

```typescript
export interface OutboxEntry {
  id: string;
  channelId: string;
  content: string;
  createdAt: number;
  status: 'pending' | 'sending' | 'failed' | 'sent';
  /** Epoch the message was minted in; refreshed on each flush attempt
   *  so a stale proof is not replayed. */
  proofEpoch: number;
  retryCount: number;
}
```

#### Send semantics

**Implementations MUST attempt the send and queue on failure. They MUST
NOT decide in advance whether a peer is reachable.**

Reachability is a prediction, and predictions about a network are wrong.
A transport can hold a connection it believes is live for as long as it
takes to notice otherwise — QUIC needs a timeout, and a bridged host may
never report the loss at all. A client that publishes on the strength of
that belief, and lets the resulting error escape, leaves the message in
local history, in no retry queue, and the caller with no way to tell.
That is a silent loss, and it is the failure this clause exists to
prevent.

Consequently:

1. A send that fails for any reason MUST enter the outbox.
2. `sendMessage` MUST NOT reject merely because a peer has gone. Callers
   determine delivery state from the outbox and `getNetworkStatus()`, not
   from an exception.
3. Replay MUST be idempotent. The outbox preserves the message `id`, and
   channel documents key messages by `id` (RFC 002 §3.1), so a peer that
   did receive a message converges on the same entry rather than showing
   it twice. This is what makes queue-on-failure safe when a fan-out
   partially succeeded.

#### Delivery scope

Publishing MUST be scoped to the conversation, not to the peer set. A
node typically holds sessions with peers belonging to different
conversations, and fanning a message out to every paired peer discloses
each conversation to all of them — independently of, and in addition to,
any leak through synchronisation.

`publish` MUST report how many peers it reached. Fanning out to an empty
set otherwise resolves exactly as a successful send does, so a message
with no eligible recipient is marked delivered and never queued.

#### Liveness

A peer registry MUST determine liveness from connection **state**, never
from the presence of a connection object. A transport that tears a
connection down marks it disconnected and wipes its session key, but the
object may remain referenced; treating that as "connected" reports the
peer as reachable indefinitely, keeps the client believing it is online,
and renders the outbox unreachable for the life of the process.

Connections that are no longer active MUST be released, and pairing MUST
survive that release — it is a decision the application made, not a
property of the transport.

#### Reconnection

Queueing is half a recovery; something has to notice the peer is back.
Implementations MUST drain the outbox when a connection is established,
in **both** directions — whether this node dialled the peer or the peer
dialled it. A flush that fails MUST leave entries queued for the next
attempt and MUST NOT turn a successful connection into a failed one.

### 7.6 Voucher Record Schema
The local voucher store MUST persist a concrete voucher record schema so redeemed vouchers can be deduplicated and garbage-collected safely.

```typescript
export interface VoucherRecord {
  nullifier: string;
  voucherCiphertext: string;
  redeemedAt: number;
  redeemerIdentityCommitment: string;
  proofOfReceipt: string;
  expiresAt: number;
}
```

---

## 8. Acceptance Criteria

- [x] `@dicsussion/sdk` initializes cleanly in Node, in a webview over a bridged transport, and in a browser, without blocking the thread that renders.
- [x] A message sent to a peer that has gone is queued rather than lost, and is delivered when that peer reconnects.
- [ ] SQLite/IndexedDB persistence stores, retrieves, and syncs Automerge deltas locally and across P2P peers.
- [ ] Persistent Web Worker pools generate and verify ZekPoc proofs without crashing the background process.
- [ ] Base trust score for all unverified contacts accurately defaults to $S_{\text{base}} = 0$.
- [ ] End-to-end integration tests verify `client.chat.sendMessage()` executes worker witness generation, encrypts payloads, and syncs via Iroh QUIC/Automerge.