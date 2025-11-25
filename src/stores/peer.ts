import { defineStore } from 'pinia'
import { Peer } from 'peerjs'
import { shallowReactive, shallowRef } from 'vue'
import { Connection } from '@/utils/connection'

export const usePeerStore = defineStore('peer', () => {
  const _peer = new Peer()
  _peer.once('open', (id) => {
    console.log('Peer connected with ID:', id)
    peer.value = _peer
  })
  _peer.on('connection', async _connection => {
    const connection_ = await Connection.handleConnect(_connection)
    connection.add(connection_)
    connection_.connect.on('close', () => {
      connection.delete(connection_)
    })
  })
  const peer = shallowRef<Peer>()
  const connection = shallowReactive(new Set<Connection>())
  return { peer, connection }
})