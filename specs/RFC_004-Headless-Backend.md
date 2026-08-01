# RFC 004: Headless Backend Engine, Web-of-Trust Storage & Client SDK

- **Target Module:** `@dicsussion/sdk` (`packages/HLessEnd`)
- **Status:** Draft
- **Author:** Parth
- **Last Updated:** 2026-07-30

---

## 1. Overview

This specification defines the Headless Backend Engine and Client SDK (`@dicsussion/sdk`) that acts as the primary orchestrator facade for the Dicsussion application. It encapsulates local persistence in SQLite or IndexedDB, Electron IPC process isolation, local Web-of-Trust (WoT) score calculations, and a persistent Web Worker pool for the ZekPoc (Zero Knowledge Proof of Chat) cryptographic protocol.

Application frontends import this SDK as a single library to access chat, group, identity, and zero-knowledge reputation features without directly managing low-level graph sockets or process executions.

---

## 2. Non-Goals

* **UI & Framework Rendering:** Providing React components, DOM elements, CSS styles, or platform-specific UI widgets.
* **Low-Level Wire Protocols:** Defining raw binary frame headers or network socket drivers.

---

## 3. Runtime Architecture & Process Isolation

To guarantee 60 FPS UI performance on desktop environments, the SDK completely isolates heavy cryptographic calculations and local persistence routines from the main rendering process using Electron IPC channels.

### 3.1 Multi-Process Execution Topology

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      MAIN THREAD (Renderer / UI)                       │
│           Dicsussion Frontend  <--->  DicsussionClient Facade          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Electron IPC Bridge
┌───────────────────────────────────▼────────────────────────────────────┐
│                    NODE.JS BACKGROUND PROCESS (Core)                   │
│  • P2P Transport Orchestration                                         │
│  • Local Web-of-Trust Score Calculator                                 │
│  • Persistent Web Worker Pool for Proof Generation                    │
└───────────────┬────────────────────────────────────────┬───────────────┘
                │                                        │
                ▼                                        ▼
┌───────────────────────────────┐        ┌───────────────────────────────┐
│  SQLITE / INDEXEDDB STORE     │        │ WEB WORKER POOL (BACKGROUND) │
│ • Local Node Persistence      │        │ • Persistent worker pool     │
│ • Automerge State Sync        │        │ • Timeout-safe proof gen     │
│ • Encrypted Key Vault         │        │ • Crash recovery / health    │
└───────────────────────────────┘        └───────────────────────────────┘
```

---

## 4. Local Persistence & State Storage

The SDK utilizes **SQLite** for desktop contexts and **IndexedDB** for browser contexts as the local-first persistence layer. Nodes persist state locally and synchronize Automerge deltas directly over Iroh QUIC streams.

### 4.1 Storage Layout

The local store is partitioned into logical collections:

1. **`identity`**: Holds local keypairs (Ed25519, X25519), ZekPoc identity secrets, and encrypted mnemonic backups.
2. **`wot_peers`**: Maps peer `did:key` identifiers to interaction counters, verified chat histories, and computed subjective trust scores.
3. **`voucher_redeemed`**: Tracks blind endorsement voucher tokens (`+5 POC` gifts) and redemption nullifiers to prevent double-spending.
4. **`channel_meta`**: Stores metadata, peer lists, and access control thresholds for active chat channels.
5. **`message_stream`**: Stores end-to-end encrypted message payloads and their proof metadata.

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
}

export interface NetworkStatus {
  connected: boolean;
  peerCount: number;
  relayActive: boolean;
  lastSyncTimestamp: number;
}

export class DicsussionClient {
  public readonly chat: ChatService;
  public readonly groups: GroupService;
  public readonly trust: TrustService;
  public readonly identity: IdentityService;
  public readonly onNetworkStatus: EventEmitter<NetworkStatus>;

  private constructor(config: ClientConfig) {
    this.chat = new ChatService();
    this.groups = new GroupService();
    this.trust = new TrustService();
    this.identity = new IdentityService();
  }

  public static async init(config: ClientConfig = {}): Promise<DicsussionClient> {
    const client = new DicsussionClient(config);
    await client.bootstrapInternalEngine();
    return client;
  }

  async disconnect(): Promise<void> {
    // Unsubscribe listeners, flush outbox, disconnect Iroh peers, reset worker pool
  }

  private async bootstrapInternalEngine(): Promise<void> {
    // Initializes Electron IPC bridge & connects to local SQLite/IndexedDB persistence
  }
}
```

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
}
```

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

### 7.3 Missing Service APIs
The SDK surface MUST expose concrete service definitions for group management and identity lifecycle operations so the client can create, recover, and rotate identities without reaching into undocumented internals.

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
}
```

### 7.4 Offline Queue & Listener Safety
The backend MUST define an offline outbox queue for pending messages and reconnect state. Each outbox entry SHOULD include status and timestamps so stale proofs can be re-generated when the client reconnects. In addition, `ChatService.onMessage()` MUST enforce a per-channel listener cap and clean up listeners when channels are destroyed.

```typescript
export interface OutboxEntry {
  id: string;
  channelId: string;
  content: string;
  proof: ZekPocProofOutput;
  createdAt: number;
  status: 'pending' | 'sending' | 'failed' | 'sent';
}
```

### 7.5 Voucher Record Schema
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

- [ ] `@dicsussion/sdk` initializes cleanly over Electron IPC without blocking the UI renderer thread.
- [ ] SQLite/IndexedDB persistence stores, retrieves, and syncs Automerge deltas locally and across P2P peers.
- [ ] Persistent Web Worker pools generate and verify ZekPoc proofs without crashing the background process.
- [ ] Base trust score for all unverified contacts accurately defaults to $S_{\text{base}} = 0$.
- [ ] End-to-end integration tests verify `client.chat.sendMessage()` executes worker witness generation, encrypts payloads, and syncs via Iroh QUIC/Automerge.