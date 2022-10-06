console.log("hi");

var jose = require("node-jose");
const fs = require("fs");

var keystore = jose.JWK.createKeyStore();

var key;
const publicKey = Buffer.from(
  fs.readFileSync("public.pem", { encoding: "utf-8" })
);

console.log("set header and option");
var options = { use: "enc" };
var header = { alg: "RSA-OAEP-256", typ: "JWT", enc: "A128CBC-HS256" };

var josePublicKey;

jose.JWK.asKey(publicKey, "pem", { ...options, ...header }).then(function (
  result
) {
  //console.log("public key = " + JSON.stringify(result));
  josePublicKey = result;
});

const privateKey = Buffer.from(
  fs.readFileSync("private.pem", { encoding: "utf-8" })
);

jose.JWK.asKey(privateKey, "pem", { ...options, ...header }).then(function (
  result
) {
  //console.log("private key = " + JSON.stringify(result));
  let decryptionKey = result;
  const input = Buffer.from(
    fs.readFileSync("jwe.txt", { encoding: "utf-8" })
  );

  //console.log("input is " + input);

  async function yomama() {
    console.log("is this async decription key : " + JSON.stringify(decryptionKey));
    // let decrypter = await jose.JWE.createDecrypt(decryptionKey);
    // let result = await decrypter.decrypt(input);
    // console.log(JSON.stringify(result));
    console.log("=================");

    function retrieveCryptoKey(header, options) {
      return jose.JWK.asKey(privateKey, "pem", {...options, ...header});
    }


    return retrieveCryptoKey(header, {direction:'decrypt'})
      .then( async decryptionKey => {
        console.log("debug 1");
        try {
          let decrypter = await jose.JWE.createDecrypt(decryptionKey);
          console.log("debug 2 " + input);
          let result = await decrypter.decrypt(input.toString());
          console.log("debug 3 " + JSON.stringify(result));  
        } catch (error) {
          console.error(error);
        }
        
        // {result} is a Object with:
        // *  header: the combined 'protected' and 'unprotected' header members
        // *  protected: an array of the member names from the "protected" member
        // *  key: Key used to decrypt
        // *  payload: Buffer of the decrypted content
        // *  plaintext: Buffer of the decrypted content (alternate)
        let td = new TextDecoder('utf-8'),
            stringPayload = td.decode(result.payload),
            parsedPayload = null;
        try {
          parsedPayload = JSON.parse(stringPayload);
        } catch (e) {
          // not JSON. It's a JWE, not JWT
        }
        if (parsedPayload) {
          let prettyPrintedJson = JSON.stringify(parsedPayload,null,2),
          reasons = checkValidityReasons(result.header, parsedPayload, getAcceptableEncryptionAlgs(decryptionKey)),
          elementId = 'token-decoded-payload',
          flavor = 'payload';
          editors[elementId].setValue(prettyPrintedJson);
          $('#' + flavor + ' > p > .length').text('( ' + stringPayload.length + ' bytes)');
          if (reasons.length == 0) {
            let message = "The JWT has been decrypted successfully, and the times are valid.";
            if (event) {
              setAlert(message, 'success');
            }
            $('#privatekey .CodeMirror-code').removeClass('outdated');
            $('#publickey .CodeMirror-code').removeClass('outdated');
          }
          else {
            let label = (reasons.length == 1)? 'Reason' : 'Reasons';
            setAlert('The JWT is not valid. ' + label+': ' + reasons.join(', and ') + '.', 'warning');
          }
          return {};
        }

        // it's a JWE
        let elementId = 'token-decoded-payload', flavor = 'payload';
        editors[elementId].setValue(stringPayload);
        $('#' + flavor + ' > p > .length').text('( ' + stringPayload.length + ' bytes)');
      })
      .catch( e => {
        // setAlert('Decryption failed. Bad key?');
        console.log('During decryption: ' + e);
        console.log(e.stack);
      });






  };

  yomama();

  // var opts = {
  //   algorithms: ["*", "RSA*"]
  // };
  // jose.JWE.createDecrypt(key, opts).
  //       decrypt(input).
  //       then(function(result) {
  //         // ...
  //         console.log(JSON.stringify(result));
  //       });

  // jose.JWE.createDecrypt(key).
  //       decrypt(input).
  //       then(function(result) {
  //         // ...
  //         console.log(result);
  //       });

  //var output = jose.util.base64url.decode(input);
  //console.log(JSON.stringify(output));
  //console.log(output);
  //fs.writeFileSync('decoded_data.txt', output.toString('utf-8'), { encoding: 'utf-8' })


});



