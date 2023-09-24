const { subtle } = globalThis.crypto;

const fromHexString = (hexString) =>
  Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}
 
// Convert a byte array to a hex string
function bytesToHex(bytes) {
    let hex = [];
    for (let i = 0; i < bytes.length; i++) {
        let current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return hex.join("");
}
function byteToUint8Array(byteArray) {
    var uint8Array = new Uint8Array(byteArray.length);
    for(var i = 0; i < uint8Array.length; i++) {
        uint8Array[i] = byteArray[i];
    }
 
    return uint8Array;
}

const EXPECTED = "4e474d5072656b65795369676e6174757265e6565a7b37344b65f695db4f80d4515532a075cbb27a3d4dcbda949e9a571a640000c068e343d941"
const SIGNED = "54e0dc4956f7ce0e559b83e0d93d3a2d41074b59992100ab8a71c807fa50d6d2053da7f16621c799486f821a6ac627ffc76b4d63c11b9c75ef8c85d15c54aff4"
const DEV_KEY = "04ab72d39f38cbadfc8914e45726ec9a41732fad9eb6e6e536ea6ef6b954328a030fe1ed4c3332c98f91d4c079d43163e865d6c23b33394c69a131f51415ff0eda"

async function test() {
  let key = await subtle.importKey("raw",byteToUint8Array(hexToBytes(DEV_KEY)),{
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["verify"],
  );
  let signature = byteToUint8Array(hexToBytes(SIGNED))
 
  let expected = byteToUint8Array(hexToBytes(EXPECTED));
  console.log(key);
  let t = await subtle.verify({
    name: "ECDSA",
    hash: "SHA-256"
  }, key, signature, expected)
  console.log(t)
}

const DEV_PRIV_KEY = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420a1b2ef67c92859ae7677c7bcc657c33fac4059448aff9602b8e6a313aa0d17caa144034200044eaf956b8619406cfd506232ded21fd5349f1ac8acc28b3b73bc8e293bc56ee0e4cfb4c9baf3c7603baa7716d0fe9c781e48f4bba5f90167f68d7f6c0e4b8cd8"
async function test2() {
    //console.log(Uint8Array.from(Buffer.from(DEV_PRIV_KEY, 'hex')))
    let key = await subtle.importKey("pkcs8",fromHexString(DEV_PRIV_KEY),{
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign"],
    );
    let to_sign = byteToUint8Array(hexToBytes(EXPECTED));

    let signature = await subtle.sign({
        name: "ECDSA",
        hash: "SHA-256"
      }, key, to_sign)
    console.log(signature)
}
(async() => {
  console.log('before start');
 
  await test();
  await test2();
  
  console.log('after start');
})();