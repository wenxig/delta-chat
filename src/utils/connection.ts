import { bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from "@noble/ciphers/utils.js"
import { BasePeer } from "./crypto"
import { gcmsiv } from '@noble/ciphers/aes.js'

import { SHA512 } from "crypto-js"
import type { DataConnection, Peer } from "peerjs"
import { shallowReactive, watch } from "vue"
import { last, Mutex } from "es-toolkit"

export type Message = ({
  type: 'text'
  content: string
  hex: string
} | {
  type: 'system'
  content: string
  hex?: undefined
} | {
  type: 'key'
  content: string[]
  hex?: undefined
} | {
  type: 'key-cpt'
  content: string[]
  hex?: undefined
}) & {
  display?: boolean
}

export class Connection {
  public messages = shallowReactive(new Array<Message>())
  public createStringMessage(data: string): Message {
    console.log('[createStringMessage] Creating string message')
    const buffer = utf8ToBytes(data)
    console.log('[createStringMessage] Encoded buffer done')
    const intermingle = this.peer.encryptArrayBuffer(buffer)
    console.log('[createStringMessage] Intermingle done')
    return {
      type: 'text',
      content: bytesToHex(intermingle.buffer),
      hex: intermingle.hex,
      display: true
    }
  }
  private keyVersion = -1
  public async sendMessage(rawMessage: Message, passVersion = false) {
    console.log('------------[sendMessage]------------')
    console.log('Is pass version', passVersion)
    if (!passVersion) {
      const requireKeyVersion = Math.floor(this.messages.length / 5)
      console.log('Require key version:', requireKeyVersion, 'Now:', this.keyVersion)
      while (requireKeyVersion != this.keyVersion) await this.generatePublicKey()
    }
    const str = JSON.stringify(rawMessage)
    const bufRaw = utf8ToBytes(str)
    console.log('Sending message', rawMessage, bufRaw)
    const buffer = gcmsiv(this.createMessageKey(this.connect.peer), this.createMessageNonce(this.connect.peer))
      .encrypt(bufRaw)
    console.log('Encrypted message done', buffer, this.createMessageKey(this.connect.peer))
    const intermingle = this.peer.encryptArrayBufferByChunk(buffer, 2)
    await this.connect.send(intermingle.buffer)
    this.messages.push(rawMessage)
    console.log('------------[/sendMessage]------------')
  }
  public addSystemMessage(content: string) {
    const message: Message = {
      type: 'system',
      display: true,
      content
    }
    this.messages.push(message)
  }

  private handleReceivedMessage(data: ArrayBufferLike) {
    console.log('[handleReceivedMessage] Received data', data)
    const deintermingle = this.peer.decryptArrayBufferByChunk(new Uint8Array(data), 2)
    const buffer = gcmsiv(this.createMessageKey(this.ins.id), this.createMessageNonce(this.ins.id))
      .decrypt(deintermingle)
    const message: Message = JSON.parse(bytesToUtf8(buffer))
    this.messages.push(message)
  }
  private decryptMessageContentCache = new Map<string, Message['content']>()
  public decryptMessageContent(message: Message) {
    const cacheKey = `${message.type}-${message.hex || message.content}`
    if (this.decryptMessageContentCache.has(cacheKey)) {
      return this.decryptMessageContentCache.get(cacheKey)!
    }
    try {
      console.log('------------[decryptMessageContent]------------')
      console.log('Content', message, message.hex)
      let result: Message['content']
      switch (message.type) {
        case 'text':
          const content = message.content
          const buffer = hexToBytes(content)
          console.log('buffer', buffer)
          const deintermingle = this.peer.decryptArrayBuffer({ buffer, hex: message.hex })
          result = bytesToUtf8(deintermingle)
          break
        default:
          result = message.content
      }
      console.log('Content done', message, result)
      console.log('------------[/decryptMessageContent]------------')
      this.decryptMessageContentCache.set(cacheKey, result)
      return result
    } catch (error) {
      console.warn(error)
      console.log('------------[/decryptMessageContent]------------')
      return message.content
    }
  }

  public createMessageKey(theyId: string) {
    const hexPart = this.messages.filter(m => m.hex).map(m => m.hex).join('')
    const salt = 'sho92j9j9edome2dimokac02maoke3' // random salt
    return utf8ToBytes(SHA512(`${hexPart}-${salt}-${theyId}-${this.peer.sharedSecret ? bytesToHex(this.peer.sharedSecret) : 'no-ss'}`).toString()).slice(0, 32)
  }
  public createMessageNonce(theyId: string) {
    return utf8ToBytes(SHA512(`哈基米哦南北绿豆-${theyId}`).toString()).slice(0, 12)
  }

  private constructor(public peer: BasePeer, public connect: DataConnection, public ins: Peer) {
    connect.on('data', (_data: any) => {
      const data: ArrayBufferLike = _data
      this.handleReceivedMessage(data)
    })
    watch(this.messages, () => {
      const lastMsg = last(this.messages)
      if (!lastMsg) return
      if (lastMsg.type == 'key') this.handleGeneratePublicKey(lastMsg)
    }, { immediate: true })
  }

  public waitMessage<S extends Message>(condition: (msg: Message) => msg is S, immediate: boolean = false) {
    const { promise, resolve } = Promise.withResolvers<S>()
    const watcher = watch(this.messages, () => {
      const lastMsg = last(this.messages)
      if (!lastMsg) return
      if (condition(lastMsg)) {
        resolve(lastMsg)
        watcher.stop()
      }
    }, { immediate })
    return promise
  }
  private generatePublicKeyLock = new Mutex
  public async generatePublicKey() {
    await this.generatePublicKeyLock.acquire()
    console.log('[generatePublicKey] begin')
    const publicKey = await this.peer.createKey()
    console.log('[generatePublicKey] PublicKey', publicKey)
    this.sendMessage({
      type: 'key',
      content: publicKey.map(v => bytesToHex(v))
    }, true)
    const msg = await this.waitMessage(m => m.type == 'key-cpt')
    await this.peer.handleHandleCreateKey(msg.content.map(v => hexToBytes(v)))
    this.keyVersion++
    this.generatePublicKeyLock.release()
  }
  public async handleGeneratePublicKey(msg: Message) {
    if (msg.type != 'key') return
    const cpt = await this.peer.handleCreateKey(msg.content.map(v => hexToBytes(v)))
    this.sendMessage({
      type: 'key-cpt',
      content: cpt.map(v => bytesToHex(v))
    }, true)
  }

  public static async connect(aimId: string) {
    const { usePeerStore } = await import('@/stores/peer')
    const store = usePeerStore()
    if (!store.peer) throw new Error('Peer not initialized')

    const connection = store.peer.connect(aimId, {
      reliable: true,
      serialization: 'binary-utf8'
    })

    await waitPeerOpen(connection)

    const peer = await BasePeer.create(store.peer.id)
    const c = new this(peer, connection, store.peer)
    c.addSystemMessage(`Connected to ${connection.peer}`)
    store.connection.add(c)
    return c
  }
  public static async handleConnect(connection: DataConnection) {
    const { usePeerStore } = await import('@/stores/peer')
    const store = usePeerStore()
    if (!store.peer) throw new Error('Peer not initialized')

    await waitPeerOpen(connection)

    const peer = await BasePeer.create(store.peer.id)
    const c = new this(peer, connection, store.peer)
    c.addSystemMessage(`Connected to ${connection.peer}`)
    return c
  }
}
const waitPeerOpen = async (connection: DataConnection) => {
  const openWatcher = Promise.withResolvers<void>()
  if (connection.open) openWatcher.resolve()
  connection.once('open', () => {
    openWatcher.resolve()
  })
  connection.once('error', err => {
    openWatcher.reject(err)
  })
  await openWatcher.promise
}