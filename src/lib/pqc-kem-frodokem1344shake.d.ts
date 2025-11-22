// Type definitions for pqc-kem-frodokem1344shake
// Generated from /mnt/data/pqc-kem-frodokem1344shake.js
// Minimal, focused typings for the public high-level API exposed by the module.

export type KeypairResult = {
  /** Public key bytes (Uint8Array) */
  publicKey: Uint8Array
  /** Private key bytes (Uint8Array) */
  privateKey: Uint8Array
}

export type EncapsulateResult = {
  /** Ciphertext bytes produced by encapsulation */
  ciphertext: Uint8Array
  /** Shared secret produced by encapsulation */
  sharedSecret: Uint8Array
}

export type DecapsulateResult = {
  /** Shared secret produced by decapsulation */
  sharedSecret: Uint8Array
}

/**
 * High-level KEM instance returned by the module initializer.
 *
 * Note:
 * - `publicKeyBytes`, `privateKeyBytes`, `ciphertextBytes`, `sharedSecretBytes`
 *   are promises that resolve to the *byte lengths* used by this KEM implementation.
 * - `keypair`, `encapsulate`, `decapsulate` are async helper methods that allocate
 *   memory in the WASM module, call into the underlying C functions and return
 *   JavaScript-friendly Uint8Array results.
 */
export interface KEM {
  /** Promise resolving to the number of bytes in a public key. */
  publicKeyBytes: Promise<number>
  /** Promise resolving to the number of bytes in a private key. */
  privateKeyBytes: Promise<number>
  /** Promise resolving to the number of bytes in a ciphertext. */
  ciphertextBytes: Promise<number>
  /** Promise resolving to the number of bytes in a shared secret. */
  sharedSecretBytes: Promise<number>

  /** Generate a keypair. Returns `{ publicKey, privateKey }`. */
  keypair(): Promise<KeypairResult>

  /**
   * Encapsulate a provided public key.
   * @param publicKey public key bytes (Uint8Array) - length should match `publicKeyBytes`.
   * @returns `{ ciphertext, sharedSecret }`.
   */
  encapsulate(publicKey: Uint8Array): Promise<EncapsulateResult>

  /**
   * Decapsulate a ciphertext using the provided private key.
   * @param ciphertext ciphertext bytes (Uint8Array) - length should match `ciphertextBytes`.
   * @param privateKey private key bytes (Uint8Array) - length should match `privateKeyBytes`.
   * @returns `{ sharedSecret }`.
   */
  decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array): Promise<DecapsulateResult>
}

/**
 * Initialize the pqc-kem-frodokem1344shake module.
 *
 * The default export is an async initializer function:
 * - If `useFallback` is true, a fallback init path is used.
 * - `locateFileOrPath` may be a string path to the WASM file or a function `(path) => string`
 *   that returns the resolved URL for the WASM file.
 *
 * Examples:
 * ```ts
 * import initKEM from "pqc-kem-frodokem1344shake";
 *
 * // basic
 * const kem = await initKEM();
 *
 * // custom wasm path
 * const kem = await initKEM(false, "/static/kem.wasm");
 *
 * // custom locator
 * const kem = await initKEM(false, (path) => `/assets/${path}`);
 * ```
 *
 * @param useFallback optional boolean; when true the initializer uses a fallback path
 * @param locateFileOrPath optional string or function used to locate the WASM file
 * @returns Promise resolving to a `KEM` instance
 */
declare function initKEM(
  useFallback?: boolean,
  locateFileOrPath?: string | ((path: string) => string)
): Promise<KEM>

export default initKEM
