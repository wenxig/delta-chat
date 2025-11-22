import "@/index.css"
import buildFrodokem from './lib/pqc-kem-frodokem1344shake'

window.begin = async () => {
  const kem = await buildFrodokem()

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