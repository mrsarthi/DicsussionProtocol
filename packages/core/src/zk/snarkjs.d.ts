/**
 * Minimal ambient types for `snarkjs`, which ships no declarations.
 *
 * Only the Groth16 surface this project uses is declared. Keeping it
 * narrow means an unexpected API change surfaces as a type error rather
 * than silently degrading to `any`.
 */
declare module 'snarkjs' {
  export namespace groth16 {
    function fullProve(
      input: Record<string, unknown>,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;

    function verify(
      verificationKey: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
  }
}
