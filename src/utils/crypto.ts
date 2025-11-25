import build, { type KEM } from '../lib/pqc-kem-frodokem1344shake.js'
import wasmUrl from '../lib/f1344shake.wasm?url'
import { AES, enc, format, mode, SHA512, } from 'crypto-js'
import { kyber } from 'kyber-crystals'
import { sum } from 'es-toolkit'


export abstract class BasePeer {
  public abstract sharedSecret?: Uint8Array<ArrayBufferLike>
  public abstract peerId?: string


  public encryptArrayBufferByChunk(buffer: ArrayBufferLike, pwd: number) {
    console.log('[encryptArrayBufferByChunk]', pwd)
    return buffer
  }

  public encryptArrayBuffer(src: Uint8Array<ArrayBufferLike>) {
    const text = new TextDecoder().decode(src.buffer)
    const hex = SHA512(text).toString()
    const allNumberOfHex = hex.match(/\d/g)?.join('') || '0'
    console.log('[encryptArrayBuffer] calculated hex:', hex, 'allNumberOfHex:', allNumberOfHex)
    let chunkNumber = allNumberOfHex
    do {
      console.log('[encryptArrayBuffer] current chunkNumber:', chunkNumber)
      chunkNumber = String(sum(chunkNumber.split('').map(n => Number(n))))
      if (chunkNumber.length <= 1) break
    } while (true)
    console.log('[encryptArrayBuffer] counted chunkNumber:', chunkNumber)
    const result = this.encryptArrayBufferByChunk(src.buffer, Number(chunkNumber))
    console.log('[encryptArrayBuffer] intermingle done')
    return {
      buffer: result,
      hex
    }
  }

  public decryptArrayBufferByChunk(buffer: ArrayBufferLike, pwd: number) {
    console.log('[decryptArrayBufferByChunk]', pwd)
    return buffer
  }
  public decryptArrayBuffer({ buffer, hex }: { buffer: ArrayBufferLike; hex: string }) {

    const allNumberOfHex = hex.match(/\d/g)?.join('') || '0'
    let chunkNumber = allNumberOfHex
    console.log('[decryptArrayBuffer] calculated hex:', hex, 'allNumberOfHex:', allNumberOfHex)
    do {
      console.log('[decryptArrayBuffer] current chunkNumber:', chunkNumber)
      chunkNumber = String(sum(chunkNumber.split('').map(n => Number(n))))
      if (chunkNumber.length <= 1) break
    } while (true)
    console.log('[decryptArrayBuffer] counted chunkNumber:', chunkNumber)


    return this.decryptArrayBufferByChunk(buffer, Number(chunkNumber))
  }
}


async function hkdfExpandConcat(secretA: Uint8Array<ArrayBufferLike>, secretB: Uint8Array<ArrayBufferLike>, infoStr = 'hybrid-ss', outLen = 32) {
  if (!window.crypto || !window.crypto.subtle || !crypto.getRandomValues) throw new Error('Web Crypto API not available')

  const subtle = window.crypto.subtle
  const concat = new Uint8Array(secretA.length + secretB.length)
  concat.set(secretA, 0)
  concat.set(secretB, secretA.length)
  const salt = new Uint8Array([1, 1, 4, 5, 1, 4])

  // Import as raw key for HKDF
  const key = await subtle.importKey('raw', concat.buffer, 'HKDF', false, ['deriveBits'])
  const info = new TextEncoder().encode(infoStr)

  const derivedBits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-512', salt: salt.buffer, info: info.buffer },
    key,
    outLen * 8
  )
  return new Uint8Array(derivedBits) // length = outLen
}

export class Initiator extends BasePeer {
  public static async create(peerId: string) {
    const kem = await build(false, wasmUrl)
    return new this(kem, peerId)
  }
  private constructor(public kem: KEM, public peerId: string) { super() }
  public sharedSecret?: Uint8Array<ArrayBufferLike>

  public async createSecret([f, k]: Uint8Array<ArrayBufferLike>[]) {
    const { ciphertext, sharedSecret: frodoSS } = await this.kem.encapsulate(f)
    const { cyphertext: cyphertext2, secret: kyberSS } = await kyber.encrypt(k)

    const finalKey = await hkdfExpandConcat(frodoSS, kyberSS, 'frodokyber-hybrid-v1', 32)
    this.sharedSecret = finalKey
    console.log('[Responder:createSecret] created shared secret:')
    console.table({
      hybrid: SHA512(finalKey.toString()).toString(),
      frodo: SHA512(frodoSS.toString()).toString(),
      kyber: SHA512(kyberSS.toString()).toString()
    })
    return [ciphertext.buffer, cyphertext2.buffer]
  }
}


export class Responder extends BasePeer {
  public static async create(peerId: string) {
    const kem = await build(false, wasmUrl)
    return new this(kem, peerId)
  }
  private constructor(public kem: KEM, public peerId: string) { super() }
  public publicKey?: Uint8Array<ArrayBufferLike>[] = []
  public privateKey?: Uint8Array<ArrayBufferLike>[] = []
  public sharedSecret?: Uint8Array<ArrayBufferLike>
  public async createKey() {
    const { publicKey: publicKey1, privateKey: privateKey1 } = await this.kem.keypair()
    const { publicKey: publicKey2, privateKey: privateKey2 } = await kyber.keyPair()
    this.privateKey = [privateKey1, privateKey2]
    this.publicKey = [publicKey1, publicKey2]
    return this.publicKey.map(pk => pk.buffer)
  }
  public async createSecret([f, k]: ArrayBufferLike[]) {
    const { sharedSecret: frodoSS } = await this.kem.decapsulate(new Uint8Array(f), this.privateKey![0])
    const kyberSS = await kyber.decrypt(new Uint8Array(k), this.privateKey![1])
    delete this.privateKey
    delete this.publicKey
    const finalKey = await hkdfExpandConcat(frodoSS, kyberSS, 'frodokyber-hybrid-v1', 32)
    this.sharedSecret = finalKey
    console.log('[Responder:createSecret] created shared secret:')
    console.table({
      hybrid: SHA512(finalKey.toString()).toString(),
      frodo: SHA512(frodoSS.toString()).toString(),
      kyber: SHA512(kyberSS.toString()).toString()
    })
    return finalKey.buffer
  }
}