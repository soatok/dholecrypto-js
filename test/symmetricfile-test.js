const assert = require('assert');
const base32 = require('rfc4648').base32;
const base64url = require('rfc4648').base64url;
const {expect} = require('chai');
const fs = require('fs');
const fsp = fs.promises;
const hex = require('rfc4648').base16;
const loadJsonFile = require('load-json-file');
const SymmetricFile = require('../lib/SymmetricFile');
const sodium = require('sodium-native');
const Util = require('../lib/Util');

describe('SymmetricFile', function() {
    it('hash()', async function() {
        let buf;
        let i = 1;
        let file;
        let a;
        let b = Buffer.alloc(64);
        let random;
        for (let len of [32, 64, 100, 1000, 10000]) {
            buf = base32.stringify(Util.randomBytes(len));
            await fsp.writeFile(__dirname + "/test" + i + ".txt", buf);
            file = await fsp.open(__dirname + "/test" + i + ".txt", 'r');

            // First test case...
            a = await SymmetricFile.hash(file);
            sodium.crypto_generichash(b, Util.stringToBuffer(buf));
            expect(hex.stringify(a)).to.be.equal(hex.stringify(b));

            // Second test case...
            random = Util.randomBytes(32);
            a = await SymmetricFile.hash(file, random);
            sodium.crypto_generichash(
                b,
                Buffer.concat([random, Util.stringToBuffer(buf)])
            );
            expect(
                hex.stringify(a)
            ).to.be.equal(
                hex.stringify(
                    Buffer.concat([random, b])
                )
            );
            await file.close();
            await fsp.unlink(__dirname + "/test" + i + ".txt");
            i++;
        }
    });
});
