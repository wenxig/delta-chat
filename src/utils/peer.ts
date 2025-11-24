import { Initiator, Responder, type BasePeer } from "./crypto"
import { usePeerStore } from "@/stores/peer"
import type { DataConnection } from "peerjs"
import { shallowReactive } from "vue"

export type RawMessage = {
  type: 'text'
  buffer: ArrayBufferLike
  hex: string
}
export type Message = {
  type: 'text'
  data: string
}

export class Connection {
  public messages = shallowReactive(new Array<Message>())
  public createStringMessage(data: string): RawMessage {
    const buffer = new TextEncoder().encode(data).buffer
    const intermingle = this.peer.intermingleArrayBuffer(new Uint8Array(buffer))
    return {
      type: 'text' as const,
      buffer: intermingle.buffer,
      hex: intermingle.hex
    }
  }
  private constructor(public peer: BasePeer, public connect: DataConnection) { }
  public static async connect(aimId: string) {
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
    return new this(peer, connection)
  }

  public static async handleConnect(connection: DataConnection) {

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
    return new this(peer, connection)
  }
}