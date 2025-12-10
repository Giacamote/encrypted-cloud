// static/js/group_keys.js
// depends on crypto.js helpers (bufToBase64, base64ToBuf)

async function deriveKeyFromPassphrase(passphrase, salt_b64=null) {
  const salt = salt_b64 ? base64ToBuf(salt_b64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const pwKey = await crypto.subtle.importKey("raw", strToBuf(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 200_000,
      hash: "SHA-256"
    },
    pwKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  // return both AES key and salt (salt required to derive same key)
  return { key, salt_b64: bufToBase64(salt) };
}

async function encryptPrivateBlobWithPass(pkcs8_b64, passphrase) {
  const { key, salt_b64 } = await deriveKeyFromPassphrase(passphrase);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, base64ToBuf(pkcs8_b64));
  // store iv + salt + ciphertext as base64 JSON
  return JSON.stringify({
    salt_b64,
    iv_b64: bufToBase64(iv.buffer),
    ciphertext_b64: bufToBase64(encrypted)
  });
}

async function decryptPrivateBlobWithPass(jsonStr, passphrase) {
  const obj = JSON.parse(jsonStr);
  const { key } = await deriveKeyFromPassphrase(passphrase, obj.salt_b64);
  const iv = base64ToBuf(obj.iv_b64);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv) }, key, base64ToBuf(obj.ciphertext_b64));
  return bufToBase64(decrypted); // returns pkcs8 base64
}

// Generate keys for a group, store encrypted private locally and upload public SPKI
async function generateAndStoreGroupKeys(groupId, passphrase) {
  // RSA-OAEP wrap key
  const wrapKeyPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );
  const wrapPub = await crypto.subtle.exportKey("spki", wrapKeyPair.publicKey);
  const wrapPriv = await crypto.subtle.exportKey("pkcs8", wrapKeyPair.privateKey);

  // ECDSA sign key
  const signKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const signPub = await crypto.subtle.exportKey("spki", signKeyPair.publicKey);
  const signPriv = await crypto.subtle.exportKey("pkcs8", signKeyPair.privateKey);

  // encrypt private keys with passphrase
  const encWrapPrivJson = await encryptPrivateBlobWithPass(bufToBase64(wrapPriv), passphrase);
  const encSignPrivJson = await encryptPrivateBlobWithPass(bufToBase64(signPriv), passphrase);

  // store locally (localStorage — consider IndexedDB for real apps)
  localStorage.setItem(`group_${groupId}_wrap_priv_enc`, encWrapPrivJson);
  localStorage.setItem(`group_${groupId}_sign_priv_enc`, encSignPrivJson);

  // upload public keys to server (base64 SPKI strings)
  const payload = {
    public_wrap_spki: bufToBase64(wrapPub),
    public_sign_spki: bufToBase64(signPub)
  };
  const res = await fetch(`/group_keys/${groupId}/upload`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("failed uploading public keys");
  return true;
}

// helper to get decrypted private key CryptoKey for group (for wrapping/unwrapping)
async function importGroupPrivateKeysFromLocal(groupId, passphrase) {
  const encWrap = localStorage.getItem(`group_${groupId}_wrap_priv_enc`);
  const encSign = localStorage.getItem(`group_${groupId}_sign_priv_enc`);
  if (!encWrap || !encSign) throw new Error("No stored group private keys");

  const wrapPrivPkcs8_b64 = await decryptPrivateBlobWithPass(encWrap, passphrase);
  const signPrivPkcs8_b64 = await decryptPrivateBlobWithPass(encSign, passphrase);

  const wrapPrivKey = await importWrappingPrivateKey(wrapPrivPkcs8_b64);
  const signPrivKey = await importSigningPrivateKey(signPrivPkcs8_b64);
  return { wrapPrivKey, signPrivKey };
}
