const assert = require('assert');
const base32 = require('rfc4648').base32;
const base64url = require('rfc4648').base64url;
const {expect} = require('chai');
const fs = require('fs');
const fsp = fs.promises;
const hex = require('rfc4648').base16;
const loadJsonFile = require('load-json-file');
const SymmetricFile = require('../lib/SymmetricFile');
const Util = require('../lib/Util');
const { SodiumPlus } = require('sodium-plus');
let sodium;

describe('SymmetricFile', function() {
    it('hash()', async function() {
        if (!sodium) sodium = await SodiumPlus.auto();
        let buf;
        let i = 1;
        let file;
        let a, b;
        let random;
        for (let len of [32, 64, 100, 1000, 10000]) {
            buf = base32.stringify(await Util.randomBytes(len));
            await fsp.writeFile(__dirname + "/test" + i + ".txt", buf);
            file = await fsp.open(__dirname + "/test" + i + ".txt", 'r');

            // First test case...
            a = await SymmetricFile.hash(file);
            b = await sodium.crypto_generichash(Util.stringToBuffer(buf), null, 64);
            expect(hex.stringify(a)).to.be.equal(hex.stringify(b));

            // Second test case...
            random = await Util.randomBytes(32);
            a = await SymmetricFile.hash(file, random);
            b = await sodium.crypto_generichash(
                Buffer.concat([random, Util.stringToBuffer(buf)]),
                null,
                64
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
        i++;
        buf = base32.stringify(await Util.randomBytes(32));
        let finExpect = await sodium.crypto_generichash(Util.stringToBuffer(buf), null, 64);
        await fsp.writeFile(__dirname + "/test" + i + ".txt", buf);
        let finHash = await SymmetricFile.hash(__dirname + "/test" + i + ".txt");
        await fsp.unlink(__dirname + "/test" + i + ".txt");
        expect(hex.stringify(finHash)).to.be.equal(hex.stringify(finExpect));
    });
});
