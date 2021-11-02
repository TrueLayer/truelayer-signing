"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
exports.__esModule = true;
exports.SignatureError = void 0;
/** Sign/verification error */
var SignatureError = /** @class */ (function (_super) {
    __extends(SignatureError, _super);
    function SignatureError(message) {
        var _this = _super.call(this, message) || this;
        _this.name = 'SignatureError';
        return _this;
    }
    SignatureError.ensure = function (condition, msg) {
        if (!condition)
            throw new SignatureError(msg);
    };
    return SignatureError;
}(Error));
exports.SignatureError = SignatureError;
