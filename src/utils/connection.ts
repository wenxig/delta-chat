import { Initiator, Responder, type BasePeer } from "./crypto"

import { AES, enc, format, SHA512 } from "crypto-js"
import type { DataConnection, Peer } from "peerjs"
import { shallowReactive } from "vue"

export type Message = {
  type: 'text'
  content: string
  hex: string
} | {
  type: 'system'
  content: string
  hex?: undefined
}

export class Connection {
  public messages = shallowReactive(new Array<Message>())
  public createStringMessage(data: string): Message {
    console.log('[createStringMessage] Creating string message')
    const buffer = new TextEncoder().encode(data).buffer
    console.log('[createStringMessage] Encoded buffer done')
    const intermingle = this.peer.encryptArrayBuffer(new Uint8Array(buffer))
    console.log('[createStringMessage] Intermingle done')
    return {
      type: 'text' as const,
      content: new TextDecoder().decode(buffer),
      hex: intermingle.hex
    }
  }
  public async sendMessage(rawMessage: Message) {
    console.log('[sendMessage] Sending message', rawMessage)
    const str = JSON.stringify(rawMessage)
    const encrypt = AES.encrypt(str, this.createMessageKey(this.connect.peer)).toString(format.OpenSSL)
    console.log('[sendMessage] Encrypted message done', encrypt, this.createMessageKey(this.connect.peer))
    const buffer = new TextEncoder().encode(encrypt).buffer
    const intermingle = this.peer.encryptArrayBufferByChunk(buffer, buffer.byteLength % 16 + 1)
    await this.connect.send(intermingle)
    this.messages.push(rawMessage)
  }
  public addSystemMessage(content: string) {
    const message: Message = {
      type: 'system',
      content
    }
    this.messages.push(message)
  }

  private handleReceivedMessage(data: ArrayBufferLike) {
    console.log('[handleReceivedMessage] Received data', data)
    const intermingle = this.peer.decryptArrayBufferByChunk(data, data.byteLength % 16 + 1)
    const text = new TextDecoder().decode(intermingle)
    const openSSL = format.OpenSSL.parse(text)
    console.log('[handleReceivedMessage] Deintermingle done', text, openSSL, this.createMessageKey(this.ins.id))
    const decrypt = AES.decrypt(openSSL, this.createMessageKey(this.ins.id))
    const decryptedStr = decrypt.toString(enc.Utf8)
    const message: Message = JSON.parse(decryptedStr)
    this.messages.push(message)
  }
  private decryptMessageContentCache = new Map<string, string>()
  public decryptMessageContent(message: Message) {
    const cacheKey = `${message.type}-${message.hex || message.content}`
    if (this.decryptMessageContentCache.has(cacheKey)) {
      return this.decryptMessageContentCache.get(cacheKey)!
    }
    let result: string
    switch (message.type) {
      case 'system':
        result = message.content
        break
      case 'text':
        const content = message.content
        const buffer = new TextEncoder().encode(content).buffer
        const deintermingle = this.peer.decryptArrayBufferByChunk(buffer, buffer.byteLength % 16 + 1)
        result = new TextDecoder().decode(deintermingle)
        break
    }
    this.decryptMessageContentCache.set(cacheKey, result)
    return result
  }

  public createMessageKey(theyId: string) {
    if (!this.peer.sharedSecret) throw new Error('Shared secret not established')
    const hexPart = this.messages.filter(m => m.hex).map(m => m.hex).join('')
    const salt = 'sho92j9j9edome2dimokac02maoke3' // random salt
    return SHA512(`${hexPart}-${salt}-${theyId}-${new TextDecoder().decode(this.peer.sharedSecret)}`).toString()
  }

  private constructor(public peer: BasePeer, public connect: DataConnection, public ins: Peer) {
  }


  public static async connect(aimId: string) {
    const { usePeerStore } = await import('@/stores/peer')
    const store = usePeerStore()
    if (!store.peer) throw new Error('Peer not initialized')
    const connection = store.peer.connect(aimId, {
      reliable: true,
      serialization: 'binary-utf8'
    })
    const openWatcher = Promise.withResolvers<void>()
    if (connection.open) openWatcher.resolve()
    connection.once('open', () => {
      openWatcher.resolve()
    })
    connection.once('error', err => {
      openWatcher.reject(err)
    })
    await openWatcher.promise

    const peer = await Initiator.create(store.peer.id)
    connection.once('data', async (data: any) => {
      c.addSystemMessage(`Received public key`)
      const cpt = await peer.createSecret(data)
      connection.send(cpt)
      c.addSystemMessage(`Key established`)
      connection.on('data', (data) => {
        c.handleReceivedMessage(data as ArrayBufferLike)
      })
    })
    const c = new this(peer, connection, store.peer)
    c.addSystemMessage(`Connected to ${connection.peer}`)
    store.connection.add(c)
    return c
  }
  public static async handleConnect(connection: DataConnection) {
    const { usePeerStore } = await import('@/stores/peer')
    const store = usePeerStore()
    if (!store.peer) throw new Error('Peer not initialized')

    const openWatcher = Promise.withResolvers<void>()
    if (connection.open) openWatcher.resolve()
    connection.once('open', () => {
      openWatcher.resolve()
    })
    connection.once('error', err => {
      openWatcher.reject(err)
    })
    await openWatcher.promise

    const peer = await Responder.create(store.peer.id)
    const pbk = await peer.createKey()
    const c = new this(peer, connection, store.peer)
    c.addSystemMessage(`Connected to ${connection.peer}`)
    c.addSystemMessage(`Creating key`)
    connection.send(pbk)
    connection.once('data', async (data: any) => {
      c.addSystemMessage(`Key established`)
      await peer.createSecret(data)
      connection.on('data', (data) => {
        c.handleReceivedMessage(data as ArrayBufferLike)
      })
    })
    return c
  }
}