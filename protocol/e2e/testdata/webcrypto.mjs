// The browser side of package e2e, with WebCrypto only (Node's globalThis.crypto
// is the same API). e2e_test.go runs it to prove both sides agree.
//
//   node webcrypto.mjs seal   <recipient_pub_b64> <info> <aad> <plaintext>  -> Box JSON
//   node webcrypto.mjs keygen                                              -> {pub, jwk}
//   node webcrypto.mjs open   <jwk_json> <info> <aad> <box_json>           -> plaintext
const { subtle } = globalThis.crypto;
const b64 = (buf) => Buffer.from(buf).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const te = new TextEncoder();

async function aesKey(priv, pub, info) {
  const bits = await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
  const hk = await subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(info) },
    hk,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

const [mode, ...args] = process.argv.slice(2);
if (mode === "seal") {
  const [pubB64, info, aad, plaintext] = args;
  const recipient = await subtle.importKey("raw", unb64(pubB64), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const key = await aesKey(eph.privateKey, recipient, info);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: te.encode(aad) }, key, te.encode(plaintext));
  const epk = await subtle.exportKey("raw", eph.publicKey);
  console.log(JSON.stringify({ alg: "ECDH-P256+HKDF-SHA256+A256GCM", epk: b64(epk), nonce: b64(nonce), ct: b64(ct) }));
} else if (mode === "keygen") {
  const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const pub = await subtle.exportKey("raw", kp.publicKey);
  const jwk = await subtle.exportKey("jwk", kp.privateKey);
  console.log(JSON.stringify({ pub: b64(pub), jwk }));
} else if (mode === "open") {
  const [jwkJSON, info, aad, boxJSON] = args;
  const priv = await subtle.importKey("jwk", JSON.parse(jwkJSON), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const box = JSON.parse(boxJSON);
  const epk = await subtle.importKey("raw", unb64(box.epk), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const key = await aesKey(priv, epk, info);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.nonce), additionalData: te.encode(aad) }, key, unb64(box.ct));
  process.stdout.write(new TextDecoder().decode(pt));
} else {
  console.error("usage: webcrypto.mjs seal|keygen|open ...");
  process.exit(2);
}
