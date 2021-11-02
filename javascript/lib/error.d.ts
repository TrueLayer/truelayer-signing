/** Sign/verification error */
export declare class SignatureError extends Error {
    constructor(message: string);
    static ensure(condition: boolean, msg: string): void;
}
