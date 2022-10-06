
const fs = require("fs");
const crypto = require("crypto");

function key2pem(flavor, keydata) {
  let body = window.btoa(String.fromCharCode(...new Uint8Array(keydata)));
  body = body.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${flavor} KEY-----\n${body}\n-----END ${flavor} KEY-----`;
}

let genKeyParams = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: {
      name: "SHA-256"
  }
};

let alg = '"RSA-OAEP-256';

const key = 
window.crypto.subtle.generateKey(genKeyParams, isExtractable, keyUse)
    .then(key =>
          window.crypto.subtle.exportKey( "spki", key.publicKey )
          .then(keydata => updateAsymmetricKeyValue('public', key2pem('PUBLIC', keydata)) )
          .then( () => window.crypto.subtle.exportKey( "pkcs8", key.privateKey ))
          .then(keydata => updateAsymmetricKeyValue('private', key2pem('PRIVATE', keydata)) ))
    .then( () => {
      $('#mainalert').removeClass('show').addClass('fade');
      $('#privatekey .CodeMirror-code').removeClass('outdated');
      $('#publickey .CodeMirror-code').removeClass('outdated');
      // why only publickey, not also privatekey?
      editors.publickey.setOption('mode', 'encodedjwt');
      return {}; })
    .catch( e => console.log(e));