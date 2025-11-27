<script setup lang='ts'>
import { reactive, ref } from 'vue'
import { usePeerStore } from './stores/peer'
import { NInput } from 'naive-ui'
import { Connection } from './utils/connection'

const aimId = ref('')
const peerStore = usePeerStore()

const messageText = reactive(<Record<string, string>>{})
</script>

<template>
  <div class="w-full border-b border-b-red-300 border-solid">
    <div class="flex">
      <NButton @click="Connection.connect(aimId.trim())">连接</NButton>
      <NInput v-model:value="aimId" />
    </div>
    <div>id: {{ peerStore.peer?.id }}</div>
  </div>

  <div class="w-full">
    <div v-for="c of peerStore.connection.values()" class="w-full border-b border-b-gray-900 border-solid">
      <div>Connection #id: {{ c.connect.peer }}</div>
      <div class="flex">
        <NButton @click="() => c.sendMessage(c.createStringMessage(messageText[c.connect.peer]))">发送</NButton>
        <NInput v-model:value="messageText[c.connect.peer]" />
      </div>
      <template v-for="m of c.messages">
        <div class="w-full border-b border-b-gray-500 border-solid" v-if="m.display">
          <span class="bg-yellow-200 mr-2">{{ m.type }}</span>
          {{ c.decryptMessageContent(m) }}
        </div>
      </template>
    </div>
  </div>
</template>