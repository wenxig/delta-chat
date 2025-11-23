<script setup lang='ts'>
import { ref } from 'vue'
import build from './lib/pqc-kem-frodokem1344shake.js'
import wasmUrl from './lib/f1344shake.wasm?url';
const begin = async () => {
  const kem = await build(false, wasmUrl)

  const { publicKey, privateKey } = await kem.keypair()

  const { ciphertext, sharedSecret: sharedSecretA } = await kem.encapsulate(publicKey)
  const { sharedSecret: sharedSecretB } = await kem.decapsulate(ciphertext, privateKey)


  console.log("CipherText Length: ", ciphertext.length)
  console.log("Cipher key: ", ciphertext)


  console.log("Bob key Length: ", sharedSecretB.length)
  console.log("Bob key: ", sharedSecretB)

  console.log("Alice key Length: ", sharedSecretA.length)
  console.log("Alice key: ", sharedSecretA)

  console.log("Alice public key length: ", publicKey.length)
  console.log("Alice public key: ", publicKey)

  console.log("Alice private key length: ", privateKey.length)
  console.log("Alice private key: ", privateKey)
}
const timer = ref(0)
setInterval(() => {
  timer.value += 0.5
}, 500)
</script>

<template>
  <div>
    <NButton @click="begin()">开始</NButton>
    {{ timer }}
  </div>
</template>