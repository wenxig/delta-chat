import build, { type KEM } from '../lib/pqc-kem-frodokem1344shake.js'
import wasmUrl from '../lib/f1344shake.wasm?url'
import { SHA256, } from 'crypto-js'
import { kyber } from 'kyber-crystals'


export abstract class BasePeer {
  public abstract sharedSecret?: Uint8Array<ArrayBufferLike>
  public abstract peerId?: string
  public intermingleArrayBuffer(src: Uint8Array<ArrayBufferLike>) {
    const text = new TextDecoder().decode(src.buffer)
    const hex = SHA256(text).toString()
    const allNumberOfHex = hex.match(/\d/g)?.join('') || '0'
    do {
      var chunkNumber = ''
      allNumberOfHex.split('').forEach((num) => {
        chunkNumber = Number(chunkNumber) + Number(num) + ''
      })
    } while (chunkNumber.length != 1)

    const total = src.length
    const parts = Math.max(1, Number(chunkNumber))

    if (parts === 1) return {
      buffer: src.buffer,
      hex
    }

    const chunks: Uint8Array[] = []
    let offset = 0
    for (let i = 0; i < parts; i++) {
      const remainingParts = parts - i
      const size = Math.floor((total - offset) / remainingParts)
      chunks.push(src.subarray(offset, offset + size))
      offset += size
    }

    const out = new Uint8Array(total)
    let pos = 0
    for (const c of chunks.reverse()) {
      out.set(c, pos)
      pos += c.length
    }

    return {
      buffer: out.buffer,
      hex
    }
  }
  public deintermingleArrayBuffer({ buffer, hex }: { buffer: ArrayBufferLike; hex: string }): ArrayBufferLike {

    const allNumberOfHex = hex.match(/\d/g)?.join('') || '0'

    let chunkNumber = ''
    do {
      chunkNumber = ''
      for (const num of allNumberOfHex.split('')) {
        chunkNumber = Number(chunkNumber) + Number(num) + ''
      }
    } while (chunkNumber.length !== 1)

    const parts = Math.max(1, Number(chunkNumber))
    if (parts === 1) return buffer

    const total = buffer.byteLength
    const sizes: number[] = []
    let offset = 0
    for (let i = 0; i < parts; i++) {
      const remainingParts = parts - i
      const size = Math.floor((total - offset) / remainingParts)
      sizes.push(size)
      offset += size
    }

    const srcView = new Uint8Array(buffer)
    const reversedChunks: Uint8Array[] = []
    let readPos = 0
    for (const s of sizes.slice().reverse()) {
      reversedChunks.push(srcView.subarray(readPos, readPos + s))
      readPos += s
    }

    const chunks = reversedChunks.reverse()
    const out = new Uint8Array(total)
    let pos = 0
    for (const c of chunks) {
      out.set(c, pos)
      pos += c.length
    }

    return out.buffer
  }
}


async function hkdfExpandConcat(secretA: Uint8Array<ArrayBufferLike>, secretB: Uint8Array<ArrayBufferLike>, infoStr = 'hybrid-ss', outLen = 32) {
  if (!window.crypto || !window.crypto.subtle || !crypto.getRandomValues) throw new Error('Web Crypto API not available')

  const subtle = window.crypto.subtle
  const concat = new Uint8Array(secretA.length + secretB.length)
  concat.set(secretA, 0)
  concat.set(secretB, secretA.length)
  const salt = crypto.getRandomValues(new Uint8Array(32))

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
    return [ciphertext, cyphertext2]
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
    return this.publicKey
  }
  public async createSecret([f, k]: Uint8Array<ArrayBufferLike>[]) {
    const { sharedSecret: frodoSS } = await this.kem.decapsulate(f, this.privateKey![0])
    const kyberSS = await kyber.decrypt(k, this.privateKey![1])
    delete this.privateKey
    delete this.publicKey
    const finalKey = await hkdfExpandConcat(frodoSS, kyberSS, 'frodokyber-hybrid-v1', 32)
    this.sharedSecret = finalKey
    return finalKey
  }
}