const assert = require('assert');
const expect = require('chai').expect;
const Util = require('../lib/Util');
const hex = require('rfc4648').base16;

describe('Util', function () {
    it('randomBytes() uniqueness', function () {
        let a = Util.randomBytes(16);
        let b = Util.randomBytes(16);
        expect(a.toString('hex')).to.not.equals(b.toString('hex'));
    });

    it ('randomInt() uniqueness', function () {
        let a, b;
        for (let i = 0; i < 1000; i++) {
            a = Util.randomInt(0, Number.MAX_SAFE_INTEGER);
            b = Util.randomInt(0, Number.MAX_SAFE_INTEGER);
            expect(a).to.not.equals(b);
        }
    });

    it ('randomInt() distribution', function () {
        let space = [0,0,0,0,0];
        let iter = 0;
        let inc;
        let i;
        let failureSpotted;
        while (iter < 10000) {
            inc = Util.randomInt(0, space.length - 1);
            space[inc]++;
            failureSpotted = false;
            for (i = 0; i < space.length; i++) {
                if (space[i] < 10) {
                    failureSpotted = true;
                    break;
                }
            }
            if (!failureSpotted) {
                break;
            }
            iter++;
        }
        expect(failureSpotted).to.be.equal(false);
        expect(iter).to.not.equals(10000);
    });
});