import { storePrivateKey, storePublicKey } from "./storeAuth";

// Algorithm Object
var algorithmKeyGen = {
  name: "RSASSA-PKCS1-v1_5",
  // RsaHashedKeyGenParams
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // Equivalent to 65537
  hash: {
    name: "SHA-256",
  },
};

var algorithmSign = {
  name: "RSASSA-PKCS1-v1_5",
};

function spkiToPEM(keydata: any) {
  var keydataS = arrayBufferToString(keydata);
  var keydataB64 = window.btoa(keydataS);
  var keydataB64Pem = formatAsPem(keydataB64);
  return keydataB64Pem;
}

function arrayBufferToString(buffer: any) {
  var binary = "";
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return binary;
}

function formatAsPem(str: any) {
  var finalString = "-----BEGIN PUBLIC KEY-----\n";

  while (str.length > 0) {
    finalString += str.substring(0, 64) + "\n";
    str = str.substring(64);
  }

  finalString = finalString + "-----END PUBLIC KEY-----";

  return finalString;
}

export const generateRsaKeyPair = async () => {
  const keyReq = await window.crypto.subtle.generateKey(algorithmKeyGen, true, [
    "sign",
    "verify",
  ]);

  const { privateKey, publicKey } = keyReq;

  let exportedPublicKey = await window.crypto.subtle.exportKey(
    "spki",
    publicKey
  );

  const publicKeyAsPEM = spkiToPEM(exportedPublicKey);

  if (!privateKey || !publicKeyAsPEM) {
    return {
      error: "Error generating keys",
    };
  }

  let unwrappedKey = await window.crypto.subtle.exportKey("jwk", privateKey);

  storePrivateKey(unwrappedKey);
  storePublicKey(publicKeyAsPEM);

  return { privateKey: privateKey, publicKey: publicKeyAsPEM };
};

export const generateDigitalSignature = async (
  privateKey: JsonWebKey,
  data: Blob
) => {
  const blobArrayBuffer = await data.arrayBuffer();

  const privateKeyAsCrypto = await window.crypto.subtle.importKey(
    "jwk",
    { ...privateKey },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["sign"]
  );

  return await window.crypto.subtle.sign(
    algorithmSign,
    privateKeyAsCrypto,
    blobArrayBuffer
  );
};

// const signData = (privateKey: string, file: Blob) => {

//   return window.crypto.subtle.sign(
//     algorithmSign,
//     key.privateKey,
//     file
//   );
// }
