"use strict";

const Util = require('../Util');

/**
 * @class SymmetricKey
 * @package dholecrypto.key
 */
module.exports = class SymmetricKey
{
    constructor(stringOrBuffer) {
        this.key = Util.stringToBuffer(stringOrBuffer);
    }

    getBuffer() {
        return this.key;
    }
};
