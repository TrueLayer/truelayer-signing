import { AWS_CONFIG, TL_CLIENT_DATA, REQUEST_DATA } from "./config.js";

/***********
 * SIGNING *
 ***********/
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import * as tlSigning from 'truelayer-signing';
import ecdsaSigFormatter from "ecdsa-sig-formatter";

const client = new KMSClient({
  region: AWS_CONFIG.region,
  credentials: AWS_CONFIG.credentials,
});

const signWithKms = async (message: string): Promise<string> => {
  const messageBuffer = Buffer.from(message);
  
  const command = new SignCommand({
    KeyId: TL_CLIENT_DATA.kmsSigningKeyId,
    SigningAlgorithm: 'ECDSA_SHA_512',
    Message: messageBuffer,
    MessageType: 'RAW',
  });
  const response = await client.send(command);

  const signatureDerBuffer = Buffer.from(response.Signature!);
  const joseSignature = ecdsaSigFormatter.derToJose(signatureDerBuffer, 'ES512');

  return joseSignature;
};

var tlSignature = await tlSigning.sign({
  kid: TL_CLIENT_DATA.publicKeyKid,
  method: <tlSigning.HttpMethod>REQUEST_DATA.method,
  path: REQUEST_DATA.path,
  headers: REQUEST_DATA.headers,
  body: REQUEST_DATA.body,
  sign: signWithKms,
});

console.log(`TL-Signature: ${tlSignature}`);

/********************
 * FETCH PUBLIC KEY *
 ********************/
import { GetPublicKeyCommand } from "@aws-sdk/client-kms";

const fetchCommand = new GetPublicKeyCommand({
  KeyId: TL_CLIENT_DATA.kmsSigningKeyId,
});
const fetchResponse = await client.send(fetchCommand);

const publicKeyDerBuffer = Buffer.from(fetchResponse.PublicKey!);
const publicKeyPem = `-----BEGIN PUBLIC KEY-----
${publicKeyDerBuffer.toString("base64").match(/.{0,64}/g)?.join(`\n`).trimEnd()}
-----END PUBLIC KEY-----`;

console.log(publicKeyPem);

/********************
 * VERIFY SIGNATURE *
 ********************/
tlSigning.verify({
  publicKeyPem: publicKeyPem,
  signature: tlSignature,
  method: <tlSigning.HttpMethod>REQUEST_DATA.method,
  path: REQUEST_DATA.path,
  headers: REQUEST_DATA.headers,
  body: REQUEST_DATA.body,
  requiredHeaders: ['Idempotency-Key'],
});
console.log("Verified!");