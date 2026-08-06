/**
 * Ambient types for `lz4js`, which ships no declarations.
 *
 * Only the block API this project uses is declared, so an unexpected
 * upstream change surfaces as a type error rather than degrading to
 * `any`.
 */
declare module 'lz4js' {
  export function compress(data: Uint8Array): Uint8Array;
  export function decompress(data: Uint8Array): Uint8Array;
}
