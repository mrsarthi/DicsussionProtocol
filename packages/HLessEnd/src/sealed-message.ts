/**
 * Messages sealed for a peer who is not there (Stream `0x0b`).
 *
 * ### Why this could not be done with what already existed
 *
 * Stream `0x02` seals under the session key agreed during the handshake,
 * and that key exists only while both peers are connected. With nobody
 * on the other end there is no session, no key, and therefore nothing
 * that could be written down and delivered later. Offline delivery was
 * not an unbuilt feature so much as an impossibility of the shape.
 *
 * A ticket already carries a static X25519 key — material that exists
 * while its owner is asleep. Sealing to that is what makes an envelope
 * storable.
 *
 * ### The envelope
 *
 * `crypto_box_seal`'s pattern: a fresh ephemeral X25519 keypair per
 * message, ECDH against the recipient's static key, HKDF to an AEAD key,
 * and the ephemeral public key shipped alongside the ciphertext so the
 * recipient can repeat the agreement. The same shape as `encryptForPeer`,
 * done here rather than through it because the signature has to name the
 * ephemeral key, which that helper generates internally and does not
 * hand back.
 *
 *     version ‖ ephemeral_pubkey ‖ nonce ‖ ciphertext+tag
 *
 * Everything identifying is **inside** the ciphertext. Outside it, an
 * envelope is a version byte and noise: whoever stores it learns neither
 * who wrote it, who it is for, nor which conversation it belongs to.
 *
 * ### What the signature covers, and why it is not just the payload
 *
 * The sender signs a transcript binding the sender, **the recipient**,
 * the channel, the message id, the time, the payload, and the ephemeral
 * public key of this particular envelope.
 *
 * Signing the payload alone would authenticate the author and still
 * allow the recipient to re-seal that exact message to a third party,
 * where it would verify as genuinely from the original sender. Naming
 * the recipient inside the signed transcript is what stops that: an
 * opener checks the transcript names *them*.
 *
 * The signature cannot cover the ciphertext, since the ciphertext
 * encrypts the payload the signature sits in.
 *
 * ### The limitation, stated plainly
 *
 * **A sealed message has no forward secrecy.** It is encrypted to a key
 * that does not rotate, so if that key ever leaks, every envelope anyone
 * captured — including ones stored months ago — opens. Live `0x02`
 * traffic is unaffected and keeps its per-session secrecy.
 *
 * The fix is X3DH one-time prekeys: a batch of public keys published in
 * advance, consumed once by a sender, the private half deleted after
 * use. That needs somewhere to publish a batch and a way to refill it
 * when exhausted — neither of which exists while no relay ships. This is
 * the honest version of the thing that works today, not the end state.
 */

import {
  base64ToBytes,
  bytesToBase64,
  decrypt,
  deriveSharedSecret,
  encrypt,
  generateX25519Keypair,
  sign,
  verify,
} from '@dicsussion/core/crypto';
import { didKeyToPublicKey } from '@dicsussion/core/transport';

import type { MessagePayload } from './message-codec.js';

/** Envelope format version, so a later shape can be told apart. */
const SEALED_VERSION = 0x01;

/**
 * Largest sealed envelope accepted, in bytes.
 *
 * A mailbox needs a number it can enforce rather than accepting whatever
 * arrives, and an opener needs the same number so the two agree. Large
 * content belongs in a blob, referenced by handle.
 */
export const MAX_SEALED_BYTES = 256 * 1024;

/**
 * How long a sealed message stays openable, in seconds.
 *
 * Bounded so a captured envelope cannot be re-delivered a year later and
 * appear as something just said. Seven days is longer than any plausible
 * mailbox delay and short enough that a replay is obvious.
 */
export const DEFAULT_MAX_AGE_S = 7 * 24 * 60 * 60;

/** Rejected if a sender's clock is this far ahead of ours. */
const MAX_CLOCK_SKEW_S = 300;

/** Why an envelope could not be opened. */
export type SealedRejection =
  | 'too-large'
  | 'malformed'
  | 'not-for-us'
  | 'bad-signature'
  | 'expired'
  | 'unpaired-sender';

/** An envelope that opened, and who actually wrote it. */
export interface OpenedSeal {
  readonly payload: MessagePayload;
  /** Proven by the signature, not merely claimed. */
  readonly senderDid: string;
  readonly sentAt: number;
}

interface SealedBody {
  readonly senderDid: string;
  readonly recipientDid: string;
  readonly payload: MessagePayload;
  readonly sentAt: number;
  readonly maxAgeS: number;
  /** Base64 Ed25519 signature over the transcript below. */
  readonly signature: string;
}

/**
 * The bytes a sender signs.
 *
 * Includes the ephemeral public key, so a signature cannot be lifted
 * onto a different envelope, and the recipient, so a message cannot be
 * re-sealed to someone else and still verify.
 */
function transcript(
  ephemeralPubkey: Uint8Array,
  senderDid: string,
  recipientDid: string,
  payload: MessagePayload,
  sentAt: number,
  maxAgeS: number,
): Uint8Array {
  const fields = JSON.stringify({
    senderDid,
    recipientDid,
    payload,
    sentAt,
    maxAgeS,
  });

  const body = new TextEncoder().encode(`dicsussion/sealed/v1|${fields}`);
  const out = new Uint8Array(ephemeralPubkey.length + body.length);

  out.set(ephemeralPubkey, 0);
  out.set(body, ephemeralPubkey.length);

  return out;
}

/**
 * Seal a message for a peer who may be offline.
 *
 * @param payload What to send, exactly as `0x02` would carry it.
 * @param senderDid Our did:key.
 * @param senderSigningSecret Our Ed25519 secret key.
 * @param recipientDid Their did:key — bound into the signature.
 * @param recipientEncryptionKey Their static X25519 key, from a ticket.
 * @returns Opaque bytes, safe to hand to anything.
 * @throws If the result would exceed `MAX_SEALED_BYTES`.
 */
export function seal(
  payload: MessagePayload,
  senderDid: string,
  senderSigningSecret: Uint8Array,
  recipientDid: string,
  recipientEncryptionKey: Uint8Array,
  options: { sentAt?: number; maxAgeS?: number } = {},
): Uint8Array {
  const sentAt = options.sentAt ?? Math.floor(Date.now() / 1000);
  const maxAgeS = options.maxAgeS ?? DEFAULT_MAX_AGE_S;

  // The agreement is done here rather than through `encryptForPeer`,
  // which generates its own ephemeral keypair and returns only the
  // public half. The transcript has to name the ephemeral key of the
  // envelope actually produced, so the keypair must exist first.
  const ephemeral = generateX25519Keypair();
  const sharedSecret = deriveSharedSecret(
    ephemeral.secretKey,
    recipientEncryptionKey,
  );

  const signature = sign(
    transcript(
      ephemeral.publicKey,
      senderDid,
      recipientDid,
      payload,
      sentAt,
      maxAgeS,
    ),
    senderSigningSecret,
  );

  const body: SealedBody = {
    senderDid,
    recipientDid,
    payload,
    sentAt,
    maxAgeS,
    signature: bytesToBase64(signature),
  };

  const { ciphertext, nonce } = encrypt(
    new TextEncoder().encode(JSON.stringify(body)),
    sharedSecret,
  );

  // The secret half has done its work and nothing else will use it.
  ephemeral.secretKey.fill(0);

  const out = new Uint8Array(1 + 32 + 12 + ciphertext.length);

  out[0] = SEALED_VERSION;
  out.set(ephemeral.publicKey, 1);
  out.set(nonce, 33);
  out.set(ciphertext, 45);

  if (out.length > MAX_SEALED_BYTES) {
    throw new Error(
      `Sealed message is ${out.length} bytes against a limit of ` +
        `${MAX_SEALED_BYTES}. Put large content in a blob and attach it.`,
    );
  }

  return out;
}

/** Everything an opener needs to decide whether to accept an envelope. */
export interface OpenContext {
  /** Our did:key — the envelope must name it. */
  readonly selfDid: string;
  /** Our X25519 secret key. */
  readonly encryptionSecret: Uint8Array;
  /** Whether a sender is paired, mirroring the rule on `0x02`. */
  readonly isPaired: (did: string) => boolean;
  /** Seconds since the epoch, injectable so age can be tested. */
  readonly now?: () => number;
}

/**
 * Open an envelope, or say why not.
 *
 * Every check that can be made without the application's help is made
 * here, because a caller holding raw bytes from a mailbox has no way to
 * make them itself.
 */
export function open(
  bytes: Uint8Array,
  context: OpenContext,
): { ok: true; opened: OpenedSeal } | { ok: false; reason: SealedRejection } {
  if (bytes.length > MAX_SEALED_BYTES) return { ok: false, reason: 'too-large' };
  if (bytes.length < 46 || bytes[0] !== SEALED_VERSION) {
    return { ok: false, reason: 'malformed' };
  }

  let plaintext: Uint8Array;
  try {
    const sharedSecret = deriveSharedSecret(
      context.encryptionSecret,
      bytes.subarray(1, 33),
    );
    plaintext = decrypt(
      bytes.subarray(45),
      bytes.subarray(33, 45),
      sharedSecret,
    );
  } catch {
    // Not for us, or tampered with. The two are indistinguishable here
    // and both mean the same thing to a caller.
    return { ok: false, reason: 'not-for-us' };
  }

  let body: SealedBody;
  try {
    body = JSON.parse(new TextDecoder().decode(plaintext)) as SealedBody;
  } catch {
    return { ok: false, reason: 'malformed' };
  }

  if (
    typeof body?.senderDid !== 'string' ||
    typeof body?.recipientDid !== 'string' ||
    typeof body?.signature !== 'string' ||
    typeof body?.sentAt !== 'number' ||
    typeof body?.maxAgeS !== 'number' ||
    typeof body?.payload !== 'object' ||
    body.payload === null
  ) {
    return { ok: false, reason: 'malformed' };
  }

  // Addressed to us, and provably so: this is inside the signature, so
  // a recipient cannot re-seal the message onward and have it verify.
  if (body.recipientDid !== context.selfDid) {
    return { ok: false, reason: 'not-for-us' };
  }

  let senderKey: Uint8Array;
  try {
    senderKey = didKeyToPublicKey(body.senderDid);
  } catch {
    return { ok: false, reason: 'malformed' };
  }

  const signed = verify(
    transcript(
      bytes.subarray(1, 33),
      body.senderDid,
      body.recipientDid,
      body.payload,
      body.sentAt,
      body.maxAgeS,
    ),
    base64ToBytes(body.signature),
    senderKey,
  );

  // Decrypting proves only that it was sealed to us. Anyone who learns a
  // mailbox address could otherwise drop in a message claiming to be
  // from anyone.
  if (!signed) return { ok: false, reason: 'bad-signature' };

  const now = (context.now ?? (() => Math.floor(Date.now() / 1000)))();
  const age = now - body.sentAt;

  // Bounded in both directions: an expired envelope is a replay, and one
  // dated far in the future would otherwise outlive its own limit.
  if (age > Math.min(body.maxAgeS, DEFAULT_MAX_AGE_S)) {
    return { ok: false, reason: 'expired' };
  }
  if (age < -MAX_CLOCK_SKEW_S) return { ok: false, reason: 'expired' };

  // The same rule live traffic obeys. Without it a mailbox address is an
  // unfiltered inbox that anyone who has ever met us can write to.
  if (!context.isPaired(body.senderDid)) {
    return { ok: false, reason: 'unpaired-sender' };
  }

  return {
    ok: true,
    opened: {
      payload: { ...body.payload, authorDid: body.senderDid },
      senderDid: body.senderDid,
      sentAt: body.sentAt,
    },
  };
}
