// generate 1024-bit RSA keys (same as your python example)
const keypair = forge.pki.rsa.generateKeyPair({ bits: 1024 });

// PEM format (compatible with Python rsa.load_pkcs1)
const publicPem = forge.pki.publicKeyToPem(keypair.publicKey);
const privatePem = forge.pki.privateKeyToPem(keypair.privateKey);

console.log(publicPem);
console.log(privatePem);

// encriptar mensaje con clave publica
const message = "hola este es un mensaje";
const encrypted = keypair.publicKey.encrypt(
  message,
  "RSAES-PKCS1-V1_5"  // matches Python rsa default
);
console.log("Encrypted (base64):", forge.util.encode64(encrypted));


// desencriptar con clave secreta
const decrypted = keypair.privateKey.decrypt(
  encrypted,
  "RSAES-PKCS1-V1_5"
);
console.log("Decrypted:", decrypted);


// firmar mensaje
const md = forge.md.sha256.create();
md.update("este es un mensaje oficial", "utf8");
const signature = keypair.privateKey.sign(md);
console.log("Signature (base64):", forge.util.encode64(signature));


// verificar firma
const md2 = forge.md.sha256.create();
md2.update("este es un mensaje oficial", "utf8");
const verified = keypair.publicKey.verify(md2.digest().bytes(), signature);
console.log("Verified:", verified); // true

// test verification
// fake message
const mdFake = forge.md.sha256.create();
mdFake.update("este es un meNsaje oficial", "utf8");

console.log(
  "Fake message verification:",
  keypair.publicKey.verify(mdFake.digest().bytes(), signature)
); // false
