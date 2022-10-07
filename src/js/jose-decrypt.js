const jose = require("node-jose");
const fs = require("fs");
const options = { use: "enc" };
// const header = { alg: "RSA-OAEP-256", typ: "JWT", enc: "A128CBC-HS256" };
const header = { alg: "RSA-OAEP-256", typ: "JWT" };

const re = {
  signed : {
    jwt : new RegExp('^([^\\.]+)\\.([^\\.]+)\\.([^\\.]+)$'),
    cm : new RegExp('^([^\\.]+)(\\.)([^\\.]+)(\\.)([^\\.]+)$')
  },
  encrypted: {
    jwt : new RegExp('^([^\\.]+)\\.([^\\.]*)\\.([^\\.]+)\\.([^\\.]+)\\.([^\\.]+)$'),
    cm :  new RegExp('^([^\\.]+)(\\.)([^\\.]*)(\\.)([^\\.]+)(\\.)([^\\.]+)(\\.)([^\\.]+)$')
  }
};

const privateKey = Buffer.from(
  fs.readFileSync("private.pem", { encoding: "utf-8" })
);

const inputJwe = Buffer.from(fs.readFileSync("jwe.txt", { encoding: "utf-8" }));

async function joseDecrypt() {
  try {
    console.log("is this async decription key2 : ");
    let decryptionKey = await jose.JWK.asKey(privateKey, "pem", {
      ...options,
      ...header,
    });
    console.log(JSON.stringify(decryptionKey));

    let decrypter = await jose.JWE.createDecrypt(decryptionKey);
    console.log("debug 2 " + inputJwe);
    // inputJwe.toString was key, it reads as utf-8 but the decrypt method is expecting string
    let result = await decrypter.decrypt(inputJwe.toString());
    console.log("debug 3 " + JSON.stringify(result));

    // this fails for marks payload, because his is url64encoded?
    let tokenString = result.payload;
    let matches = re.signed.jwt.exec(tokenString);
    if(matches && matches.length == 4){
      console.log("looks like a signed JWT");
      // we only need to decrypt the payload
      // 2nd one is the SDE payload
      var token = matches[2];
      var json = Buffer.from(token, 'base64').toString('utf8');
      try {
        var obj = JSON.parse(json), // may throw            
        flatJson = JSON.stringify(obj);
        console.log("decrypted payload is " + flatJson);
      } catch (error) {
        console.error("this might not be a json " + error);
      }
    } else {
      // if it's not signed, then the payload should just be json
      let td = new TextDecoder("utf-8"),
      stringPayload = td.decode(result.payload),
      parsedPayload = null;

    parsedPayload = JSON.parse(stringPayload);
    console.log("parsed payload = " + JSON.stringify(parsedPayload));
    }    
  } catch (error) {
    console.error(error);
  }
}

joseDecrypt();
