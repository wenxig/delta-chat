<script setup lang='ts'>
import { ref } from 'vue'
import { usePeerStore } from './stores/peer'
import { NInput } from 'naive-ui'
import { Connection } from './utils/peer'

const aimId = ref('')
const peerStore = usePeerStore()
</script>

<template>
  <div>
    <div class="flex">
      <NButton @click="Connection.connect(aimId)">连接</NButton>
      <NInput v-model:value="aimId" />
    </div>
    <div>id: {{ peerStore.peer?.id }}</div>
  </div>
  <div class="w-full">
    <div v-for="c of peerStore.connection.values()" class="w-full border-b border-b-gray-900 border-solid">
      #id: {{ c.connect.peer }}
      <div class="w-full border-b border-b-gray-500 border-solid" v-for="m of c.messages">
        {{ m.data }}
      </div>
    </div>
  </div>
</template>