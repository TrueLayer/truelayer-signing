/** Sign/verification error */
class SignatureError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SignatureError';
  }

  static ensure(condition, msg) {
    if (!condition) throw new SignatureError(msg);
  }
}

module.exports = SignatureError;
