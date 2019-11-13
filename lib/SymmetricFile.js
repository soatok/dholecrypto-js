"use strict";

const fs = require('fs');
const fsp = fs.promises;
const Util = require('./Util');
const { SodiumPlus } = require('sodium-plus');
let sodium;

const BUFFER_SIZE = 8192;

module.exports = class SymmetricFile {
    /**
     * @param {string|FileHandle} file
     * @param {string|Buffer} preamble
     * @returns {Promise<Buffer>}
     */
    static async hash(file, preamble = '') {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (typeof (file) === 'string') {
            let handle = await fsp.open(file, 'r');
            try {
                return await SymmetricFile.hashFileHandle(
                    handle,
                    preamble
                );
            } finally {
                handle.close();
            }
        }
        if (typeof(file) === 'number') {
            throw new TypeError('File must be a file handle or a path');
        }
        return await SymmetricFile.hashFileHandle(file, preamble);
    }

    /**
     *
     * @param {FileHandle} fh
     * @param {string|Buffer} preamble
     * @returns {Promise<Buffer>}
     */
    static async hashFileHandle(fh, preamble = '') {
        if (!sodium) sodium = await SodiumPlus.auto();
        let stat = await fh.stat();
        let buf = Buffer.alloc(BUFFER_SIZE);
        let state = await sodium.crypto_generichash_init(null, 64);
        let prefix = Util.stringToBuffer(preamble);
        if (prefix.length > 0) {
            await sodium.crypto_generichash_update(state, prefix);
        }

        let start = 0;
        let toRead = 0;
        while ( start < stat.size) {
            toRead = Math.min((stat.size - start), BUFFER_SIZE);
            await fh.read(buf, 0, toRead, start);
            await sodium.crypto_generichash_update(state, buf.slice(0, toRead));
            start += toRead;
        }
        let output = await sodium.crypto_generichash_final(state, 64);
        return Buffer.concat([prefix, output]);
    }
};
