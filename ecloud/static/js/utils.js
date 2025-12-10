// helpers
function bufToBase64(buffer){
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
function base64ToBuf(b64){
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
  return arr.buffer;
}
