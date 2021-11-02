"use strict";
exports.__esModule = true;
exports.Headers = void 0;
/** Http headers collection. */
var Headers = /** @class */ (function () {
    function Headers(headers) {
        this.entries = Object.entries(headers);
    }
    /** Returns header names in consistent order matching `.entries`. */
    Headers.prototype.names = function () {
        return this.entries.map(function (entry) { return entry[0]; });
    };
    /** Throws if there are any duplicate headers with different casing. */
    Headers.prototype.validated = function () {
        var names = this.names();
        var distinctNames = new Set(names.map(function (n) { return n.toLowerCase(); }));
        if (names.length !== distinctNames.size) {
            throw new Error("duplicate header names with different casing");
        }
        return this;
    };
    /** Retain headers in `tlHeaders` using the exact name casing in `tlHeaders`
     *  and sort entries to match the order of `tlHeaders`.
     */
    Headers.prototype.retainAndSort = function (tlHeaders) {
        var all = new Map();
        for (var _i = 0, _a = this.entries; _i < _a.length; _i++) {
            var _b = _a[_i], name_1 = _b[0], value = _b[1];
            all.set(name_1.toLowerCase(), value);
        }
        this.entries = tlHeaders.map(function (name) { return [name, all.get(name.toLowerCase()) || ""]; });
    };
    return Headers;
}());
exports.Headers = Headers;
