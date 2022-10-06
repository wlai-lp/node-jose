const jose = require("node-jose");
const fs = require("fs");
const options = { use: "enc" };
// const header = { alg: "RSA-OAEP-256", typ: "JWT", enc: "A128CBC-HS256" };
const header = { alg: "RSA-OAEP-256", typ: "JWT" };

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
    let td = new TextDecoder("utf-8"),
      stringPayload = td.decode(result.payload),
      parsedPayload = null;

    parsedPayload = JSON.parse(stringPayload);
    console.log("parsed payload = " + JSON.stringify(parsedPayload));
  } catch (error) {
    console.error(error);
  }
}

joseDecrypt();
