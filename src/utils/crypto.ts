import build, { type KEM } from '../lib/pqc-kem-frodokem1344shake.js'
import wasmUrl from '../lib/f1344shake.wasm?url'
import { MD5, SHA512, } from 'crypto-js'
import { kyber } from 'kyber-crystals'
import { sum } from 'es-toolkit'
import { gcmsiv } from '@noble/ciphers/aes.js'
import { bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils.js'

export class BasePeer {
  public sharedSecret?: Uint8Array<ArrayBufferLike>

  private createArrayBufferInit(pwd: number) {
    return [
      utf8ToBytes(MD5(`${this.sharedSecret ?? 'no-ss'}|${pwd}`).toString()).slice(0, 32),
      utf8ToBytes(MD5(String(pwd)).toString()).slice(0, 12)
    ] as const
  }
  public encryptArrayBufferByChunk(buffer: Uint8Array<ArrayBufferLike>, pwd: number) {
    return  gcmsiv(...this.createArrayBufferInit(pwd)).encrypt(buffer)
  }

  public encryptArrayBuffer(src: Uint8Array<ArrayBufferLike>) {
    console.log('-------------[encryptArrayBuffer]-------------')
    const text = bytesToUtf8(src)
    const hex = SHA512(text).toString()
    const allNumberOfHex = hex.match(/\d/g)?.join('') || '0'
    console.log('calculated hex:', hex, 'allNumberOfHex:', allNumberOfHex)
    let chunkNumber = allNumberOfHex
    do {
      console.log('current chunkNumber:', chunkNumber)
      chunkNumber = String(sum(chunkNumber.split('').map(n => Number(n))))
      if (chunkNumber.length <= 1) break
    } while (true)
    console.log('counted chunkNumber:', chunkNumber)
    const result = this.encryptArrayBufferByChunk(src, Number(chunkNumber))
    console.log('intermingle done')
    console.log('-------------[/encryptArrayBuffer]-------------')
    return {
      buffer: result,
      hex
    }
  }

  public decryptArrayBufferByChunk(buffer: Uint8Array<ArrayBufferLike>, pwd: number) {
    return gcmsiv(...this.createArrayBufferInit(pwd)).decrypt(buffer)
  }
  public decryptArrayBuffer({ buffer, hex }: { buffer: Uint8Array<ArrayBufferLike>; hex: string }) {
    console.log('-------------[decryptArrayBuffer]-------------')
    const allNumberOfHex = hex.match(/\d/g)?.join('') || '0'
    let chunkNumber = allNumberOfHex
    console.log('calculated hex:', hex, 'allNumberOfHex:', allNumberOfHex)
    do {
      console.log('current chunkNumber:', chunkNumber)
      chunkNumber = String(sum(chunkNumber.split('').map(n => Number(n))))
      if (chunkNumber.length <= 1) break
    } while (true)
    console.log('counted chunkNumber:', chunkNumber)


    console.log('-------------[/decryptArrayBuffer]-------------')
    return this.decryptArrayBufferByChunk(buffer, Number(chunkNumber))
  }

  private constructor(public kem: KEM, public peerId: string) { }
  public static async create(peerId: string) {
    const kem = await build(false, wasmUrl)
    return new this(kem, peerId)
  }


  public publicKey?: Uint8Array<ArrayBufferLike>[] = []
  public privateKey?: Uint8Array<ArrayBufferLike>[] = []
  public async createKey() {
    const { publicKey: publicKey1, privateKey: privateKey1 } = await this.kem.keypair()
    const { publicKey: publicKey2, privateKey: privateKey2 } = await kyber.keyPair()
    this.privateKey = [privateKey1, privateKey2]
    this.publicKey = [publicKey1, publicKey2]
    return this.publicKey
  }
  public async handleCreateKey([f, k]: Uint8Array<ArrayBufferLike>[]) {
    const { ciphertext, sharedSecret: frodoSS } = await this.kem.encapsulate(f)
    const { cyphertext: cyphertext2, secret: kyberSS } = await kyber.encrypt(k)

    const finalKey = await hkdfExpandConcat(frodoSS, kyberSS, 'frodokyber-hybrid-v1', 32)
    this.sharedSecret = finalKey
    console.log('[BasePeer.handleCreateKey] created shared secret')
    console.table({
      hybrid: SHA512(finalKey.toString()).toString(),
      frodo: SHA512(frodoSS.toString()).toString(),
      kyber: SHA512(kyberSS.toString()).toString()
    })
    return [ciphertext, cyphertext2]
  }
  public async handleHandleCreateKey([f, k]: Uint8Array<ArrayBufferLike>[]) {
    const { sharedSecret: frodoSS } = await this.kem.decapsulate(f, this.privateKey![0])
    const kyberSS = await kyber.decrypt(k, this.privateKey![1])
    delete this.privateKey
    delete this.publicKey
    const finalKey = await hkdfExpandConcat(frodoSS, kyberSS, 'frodokyber-hybrid-v1', 32)
    this.sharedSecret = finalKey
    console.log('[BasePeer.handleHandleCreateKey] created shared secret')
    console.table({
      hybrid: SHA512(finalKey.toString()).toString(),
      frodo: SHA512(frodoSS.toString()).toString(),
      kyber: SHA512(kyberSS.toString()).toString()
    })
    return finalKey
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