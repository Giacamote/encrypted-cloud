// static/js/crypto.js
// Uses WebCrypto (window.crypto.subtle). Helper utilities for hybrid encryption.

//
// Helpers: base64 <-> ArrayBuffer
//
function bufToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
function base64ToBuf(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8.buffer;
}
function strToBuf(str) {
  return new TextEncoder().encode(str);
}
function bufToStr(buf) {
  return new TextDecoder().decode(buf);
}

//
// 1) Generate signing keypair (ECDSA P-256) and wrapping keypair (RSA-OAEP)
// - Signing: ECDSA P-256 (for sign/verify)
// - Wrapping: RSA-OAEP (for encrypting AES keys)
//
async function generateUserKeys() {
  // ECDSA for signing
  const signKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true, // extractable public/private? true here so user can back up; set false to keep non-exportable
    ["sign", "verify"]
  );

  // RSA-OAEP for wrapping AES keys
  const wrapKeyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  // export public keys to send to server (SPKI)
  const signPub = await crypto.subtle.exportKey("spki", signKeyPair.publicKey);
  const wrapPub = await crypto.subtle.exportKey("spki", wrapKeyPair.publicKey);

  // export private keys if you want backup (PKCS8). Consider encrypting before storing.
  const signPriv = await crypto.subtle.exportKey("pkcs8", signKeyPair.privateKey);
  const wrapPriv = await crypto.subtle.exportKey("pkcs8", wrapKeyPair.privateKey);

  return {
    sign: {
      public_spki_b64: bufToBase64(signPub),
      private_pkcs8_b64: bufToBase64(signPriv)
    },
    wrap: {
      public_spki_b64: bufToBase64(wrapPub),
      private_pkcs8_b64: bufToBase64(wrapPriv)
    }
  };
}

//
// 2) Import helper functions for keys stored as base64 strings from localStorage/backups
//
async function importSigningPrivateKey(pkcs8_b64) {
  return crypto.subtle.importKey(
    "pkcs8",
    base64ToBuf(pkcs8_b64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}
async function importSigningPublicKey(spki_b64) {
  return crypto.subtle.importKey(
    "spki",
    base64ToBuf(spki_b64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
}
async function importWrappingPrivateKey(pkcs8_b64) {
  return crypto.subtle.importKey(
    "pkcs8",
    base64ToBuf(pkcs8_b64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
}
async function importWrappingPublicKey(spki_b64) {
  return crypto.subtle.importKey(
    "spki",
    base64ToBuf(spki_b64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

//
// 3) Create a random AES-GCM key (per file) and helpers to import/export raw
//
async function generateAesKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt","decrypt"]);
}
async function exportAesRaw(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return raw; // ArrayBuffer
}
async function importAesFromRaw(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt","decrypt"]);
}

//
// 4) Encrypt file with AES-GCM (returns {cipher_b64, iv_b64})
//
async function encryptFileWithAes(file, aesKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plainBuf = await file.arrayBuffer();
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plainBuf);
  return { cipher_b64: bufToBase64(cipherBuf), iv_b64: bufToBase64(iv.buffer) };
}

//
// 5) Decrypt ciphertext with AES-GCM
//
async function decryptAesCipherToBlob(cipher_b64, iv_b64, aesKey) {
  const cipherBuf = base64ToBuf(cipher_b64);
  const ivBuf = base64ToBuf(iv_b64);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(ivBuf) }, aesKey, cipherBuf);
  return new Blob([plainBuf]);
}

//
// 6) Sign file (sign plaintext buffer) with ECDSA (SHA-256). Returns base64 signature
//
async function signFileBuffer(file, signingPrivateKey) {
  const buf = await file.arrayBuffer();
  const sigBuf = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingPrivateKey, buf);
  return bufToBase64(sigBuf);
}

//
// 7) Verify signature (given plaintext ArrayBuffer and signature b64 and signer's public key)
//
async function verifyFileSignaturePlainBuffer(arrayBuffer, signature_b64, signingPublicKey) {
  const sigBuf = base64ToBuf(signature_b64);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, signingPublicKey, sigBuf, arrayBuffer);
}

//
// 8) Wrap AES raw key with recipient's RSA-OAEP public key
//
async function wrapAesKeyForRecipient(aesRawBuffer, recipientPublicSpki_b64) {
  const pub = await importWrappingPublicKey(recipientPublicSpki_b64);
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, aesRawBuffer);
  return bufToBase64(wrapped);
}

//
// 9) Unwrap / decrypt wrapped AES key with recipient's RSA private key (pkcs8 imported)
//
async function unwrapAesKeyWithRecipientPrivate(wrapped_b64, recipientPrivKey) {
  const wrappedBuf = base64ToBuf(wrapped_b64);
  const rawAes = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, recipientPrivKey, wrappedBuf);
  // import as AES key
  return importAesFromRaw(rawAes);
}

//
// 10) Convenience: prepare upload payload
//    - file input element (file)
//    - signPrivKey (CryptoKey), wrap recipients array [{id, public_spki_b64}]
//    Returns object {cipher_b64, iv_b64, signature_b64, wrappedKeys: [{user_id, wrapped_b64}]}
//
async function prepareEncryptedUpload(file, signingPrivKey, recipientsPublicKeys) {
  // 1) AES key + raw
  const aesKey = await generateAesKey();
  const aesRaw = await exportAesRaw(aesKey);

  // 2) Sign plaintext
  const signature_b64 = await signFileBuffer(file, signingPrivKey);

  // 3) Encrypt file
  const { cipher_b64, iv_b64 } = await encryptFileWithAes(file, aesKey);

  // 4) Wrap AES key for recipients
  const wrappedKeys = [];
  for (const r of recipientsPublicKeys) {
    const wrapped = await wrapAesKeyForRecipient(aesRaw, r.public_spki_b64);
    wrappedKeys.push({ user_id: r.id, wrapped_b64: wrapped });
  }

  return { cipher_b64, iv_b64, signature_b64, wrappedKeys };
}
