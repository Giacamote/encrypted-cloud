// static/js/crypto-upload.js
// Requires modern browser with window.crypto.subtle
// Requires helper functions: bufToBase64, base64ToBuf, strToBuf, importSigningPrivateKey, importWrappingPrivateKey
// from the crypto helpers we discussed earlier (crypto.js). Adapt names if needed.

async function arrayBufferToBlob(buffer, type) {
  return new Blob([buffer], { type });
}

async function prepareEncryptedUploadFile(file, signingPrivKey, recipientsPublicKeys) {
  //generar clave AES-GCM 
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt","decrypt"]);
  const aesRaw = await crypto.subtle.exportKey("raw", aesKey);

  //firmar archivo
  const fileBuf = await file.arrayBuffer();
  const signatureBuf = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingPrivKey, fileBuf);
  const signature_b64 = bufToBase64(signatureBuf);

  //encriptar archivo (AES-GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));//12 bytes 
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, fileBuf);

  //encriptar la clave privada del archivo para cada usuario (RSA-OAEP)
  const wrappedKeys = [];
  for (const r of recipientsPublicKeys) {
    //primero traer la llave de cada usuario del grupo
    const pub = await crypto.subtle.importKey("spki", base64ToBuf(r.public_wrap_spki), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    //encriptarla
    const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, aesRaw);
    //agrega a la lista
    wrappedKeys.push({ user_id: r.user_id, wrapped_b64: bufToBase64(wrapped) });
  }

  return {
    cipherBuf,//archivo encriptado (arraybuffer binario)
    iv_b64: bufToBase64(iv.buffer),
    signature_b64,
    wrappedKeys//lista de llaves
  };
}

// Bind to upload form submit (id or class) on dashboard
document.addEventListener("DOMContentLoaded", () => {
  const uploadForm = document.querySelector("form[action='/upload']") || document.querySelector("form[action='/api/upload_encrypted']");
  if (!uploadForm) return;

  uploadForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();

    const fileInput = uploadForm.querySelector("input[type='file'][name='file']") || uploadForm.querySelector("input[type='file']");
    const groupSelect = uploadForm.querySelector("select[name='group_id']") || uploadForm.querySelector("#group_id");
    const file = fileInput?.files?.[0];
    const groupId = groupSelect?.value || null;
    if (!file) { alert("Select a file first"); return; }

    // 0) make sure user has local group private keys stored and prompt for passphrase to unlock them
    // We assume encrypted private keys are stored in localStorage as 'group_{groupId}_wrap_priv_enc' and 'group_{groupId}_sign_priv_enc'
    const passphrase = prompt("Enter passphrase to unlock your group private keys (for signing and wrapping):");
    if (!passphrase) { alert("Passphrase required"); return; }

    // import decrypted private keys (uses helper functions from earlier group_keys.js)
    let wrapPrivKey, signPrivKey;
    try {
      const encWrap = localStorage.getItem(`group_${groupId}_wrap_priv_enc`);
      const encSign = localStorage.getItem(`group_${groupId}_sign_priv_enc`);
      if (!encWrap || !encSign) { alert("No stored private keys for this group. Generate/import group keys first."); return; }
      const wrapPrivPkcs8_b64 = await decryptPrivateBlobWithPass(encWrap, passphrase); // returns pkcs8 base64
      const signPrivPkcs8_b64 = await decryptPrivateBlobWithPass(encSign, passphrase);
      wrapPrivKey = await importWrappingPrivateKey(wrapPrivPkcs8_b64); // CryptoKey (RSA-OAEP, decrypt)
      signPrivKey = await importSigningPrivateKey(signPrivPkcs8_b64);   // CryptoKey (ECDSA sign)
    } catch (err) {
      console.error(err);
      alert("Failed to import private keys. Wrong passphrase?");
      return;
    }

    // 1) fetch recipients' public keys for the chosen group (server endpoint)
    let recipients = [];
    if (groupId) {
      try {
        const resp = await fetch(`/group_keys/${groupId}/members_public_keys`);
        if (!resp.ok) throw new Error("failed to fetch group public keys");
        recipients = await resp.json(); // expected: [{ user_id, username, public_wrap_spki, public_sign_spki }, ...]
      } catch (err) {
        console.error(err);
        alert("Failed to load group member keys");
        return;
      }
    } else {
      // upload to no group: you can decide behavior — here we will still encrypt for owner only
      recipients = [{ user_id: CURRENT_USER_ID, public_wrap_spki: null }]; // placeholder
    }

    // Map recipients into expected shape, exclude those that don't have public_wrap_spki
    const wrapRecipients = recipients.filter(r => r.public_wrap_spki).map(r => ({ user_id: r.user_id, public_wrap_spki: r.public_wrap_spki }));

    // 2) prepare encryption (cipher, iv, signature, wrappedKeys)
    let prepared;
    try {
      prepared = await prepareEncryptedUploadFile(file, signPrivKey, wrapRecipients);
    } catch (err) {
      console.error(err);
      alert("Encryption/signing failed");
      return;
    }

    // 3) Build FormData and send to server
    const formData = new FormData();
    // ciphertext as blob
    const cipherBlob = await arrayBufferToBlob(prepared.cipherBuf, file.type || "application/octet-stream");
    formData.append("cipherfile", cipherBlob, file.name + ".enc"); // saved name ends with .enc
    formData.append("original_filename", file.name);
    formData.append("mimetype", file.type);
    formData.append("iv_b64", prepared.iv_b64);
    formData.append("signature_b64", prepared.signature_b64);
    formData.append("group_id", groupId || "");
    formData.append("wrapped_keys", JSON.stringify(prepared.wrappedKeys));

    // optional CSRF header? If you're using Flask-WTF CSRF you may need to send the token (not covered here)
    try {
      const upl = await fetch("/api/upload_encrypted", { method: "POST", body: formData });
      const j = await upl.json();
      if (!upl.ok) {
        alert("Upload failed: " + (j?.error || upl.statusText));
        return;
      }
      alert("Upload OK");
      window.location.reload();
    } catch (err) {
      console.error(err);
      alert("Upload failed");
    }
  });
});
