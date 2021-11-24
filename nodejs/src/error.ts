/** Sign/verification error */
export class SignatureError extends Error {
  constructor (message: string) {
    super(message);
    this.name = 'SignatureError';
  }

  static ensure(condition: boolean, msg: string) {
    if (!condition) throw new SignatureError(msg);
  }
}

