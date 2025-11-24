import "@/index.css"
import { createApp } from "vue"
import App from "./App.vue"
import { createPinia } from 'pinia'
import send from 'random-seed'
import { enc, SHA256 } from 'crypto-js'

const timeAgo = Date.now()

const app = createApp(App)
app.use(createPinia())

const timeNow = Date.now()

const random = send.create(SHA256(
  `${Math.random()}-${timeAgo + timeNow + Date.now()}`
).toString(enc.Base64))
Math.random = () => random.floatBetween(0, 1)

app.mount('#app')