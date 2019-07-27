"use strict";

const fs = require('fs');
const fsp = fs.promises;
const sodium = require('sodium-native');
const Util = require('./Util');

const BUFFER_SIZE = 8192;

module.exports = class SymmetricFile {
    /**
     * @param {string|FileHandle} file
     * @param {string|Buffer} preamble
     * @returns {Promise<Buffer>}
     */
    static async hash(file, preamble = '') {
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
        let output = Buffer.alloc(64);
        let stat = await fh.stat();
        let buf = Buffer.alloc(BUFFER_SIZE);
        let state = sodium.crypto_generichash_instance(null, 64);
        let prefix = Util.stringToBuffer(preamble);
        if (prefix.length > 0) {
            state.update(prefix);
        }

        let start = 0;
        let toRead = 0;
        while ( start < stat.size) {
            toRead = Math.min((stat.size - start), BUFFER_SIZE);
            await fh.read(buf, 0, toRead, start);
            state.update(buf.slice(0, toRead));
            start += toRead;
        }
        state.final(output);
        return Buffer.concat([prefix, output]);
    }
};
