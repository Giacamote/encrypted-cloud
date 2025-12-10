// call when user selects file
async function encryptAndUpload(file) {
  // generate AES key
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt","decrypt"]);
  const aesRaw = await crypto.subtle.exportKey("raw", aesKey);
  console.log(aesRaw)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const fileBuf = await file.arrayBuffer();
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, fileBuf);

  // base64 outputs
  const cipherB64 = bufToBase64(cipherBuf);
  const ivB64 = bufToBase64(iv.buffer);
  const keyB64 = bufToBase64(aesRaw);

  // send ciphertext to server (multipart or JSON)
  await fetch("/upload-encrypted-file", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      filename: file.name,
      mimetype: file.type,
      iv: ivB64,
      ciphertext: cipherB64,
      // optionally uploader_id etc.
    })
  });

  // provide key to user to share
  alert("Share this key with authorized users:\n\n" + keyB64);
}

////////// generar un par (pk,sk) para firmar con ECDSA //////////
async function generateSigningKeypair() {
  const keyPair = await crypto.subtle.generateKey(
    {name: "ECDSA",namedCurve: "P-256"},
    true,
    ["sign", "verify"]
  );

  const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKeyBase64: bufToBase64(publicKey),
    privateKeyBase64: bufToBase64(privateKey)
  };
}

/////////////// funcion para firmar un archivo //////////////////
// recibe el archivo y la llave privada
async function signFile(file, privateKeyBase64) {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    base64ToBuf(privateKeyBase64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const data = await file.arrayBuffer();

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data
  );

  return bufToBase64(signature);
}

////////////// verificar una firma usando la clave publica ////////////
async function verifyFileSignature(fileArrayBuffer, signatureBase64, publicKeyBase64) {

  const publicKey = await crypto.subtle.importKey(
    "spki",
    base64ToBuf(publicKeyBase64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );

  const signature = base64ToBuf(signatureBase64);

  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    signature,
    fileArrayBuffer
  );

  return ok; // true or false
}
