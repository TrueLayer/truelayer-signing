import { randomUUID } from "crypto";

const throwMissingEnvVar: (envVarName: string) => never = (envVarName: string) => {
  throw new Error(`Expected '${envVarName}' environment variable`);
};

export const TL_CLIENT_DATA: {
  readonly publicKeyKid: string,
  readonly kmsSigningKeyId: string,
} = {
  publicKeyKid: randomUUID(),
  kmsSigningKeyId: process.env.AWS_KMS_SIGNING_KEY_ID ?? throwMissingEnvVar('AWS_KMS_SIGNING_KEY_ID'),
};

export const REQUEST_DATA: {
  readonly method: string,
  readonly path: string,
  readonly body: string,
  readonly headers: Record<string, string>,
} = {
  method: 'POST',
  path: '/v3/payments',
  body: '{"currency":"GBP","amount_in_minor":100}',
  headers: {
    'Authorization': 'Bearer my-secret-auth-token',
    'Idempotency-Key': randomUUID(),
    'traceparent': '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
  },
};

export const AWS_CONFIG: {
  readonly credentials: {
    readonly accessKeyId: string,
    readonly secretAccessKey: string,
  },
  readonly region: string,
} = {
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? throwMissingEnvVar('AWS_ACCESS_KEY_ID'),
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? throwMissingEnvVar('AWS_SECRET_ACCESS_KEY'),
  },
  region: process.env.AWS_REGION ?? throwMissingEnvVar('AWS_REGION'),
};
