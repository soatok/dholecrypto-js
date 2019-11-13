# DholeCrypto.js

[![Support on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.herokuapp.com%2Fsoatok&style=flat)](https://patreon.com/soatok)
[![Travis CI](https://travis-ci.org/soatok/dholecrypto-js.svg?branch=master)](https://travis-ci.org/soatok/dholecrypto-js)
[![npm version](https://img.shields.io/npm/v/dhole-crypto.svg)](https://npm.im/dhole-crypto)

JavaScript port of [Dhole Cryptography](https://github.com/soatok/dhole-cryptography) (PHP).

Libsodium wrapper for Soatok's JavaScript projects. Released under the very
permissive ISC license.

> Important: Until version `v1.0.0` is released, please don't deploy this library
> in any production systems. I'll tag `v1.0.0` when I'm confident in the correctness
> and security of the implementation.

## Installation

```
npm install dhole-crypto
```

## Usage

### Asymmetric Cryptography

#### Digital Signatures

```javascript
const { 
    Asymmetric, 
    AsymmetricSecretKey
} = require('dhole-crypto');

(async function () {
    let wolfSecret = await AsymmetricSecretKey.generate();
    let wolfPublic = wolfSecret.getPublicKey();
    
    let message = "Your $350 awoo fine has been paid UwU";
    
    let signature = await Asymmetric.sign(message, wolfSecret);
    if (!await Asymmetric.verify(message, wolfPublic, signature)) {
        console.log("Invalid signature. Awoo not authorized.");
    }
})();
```

#### Authenticated Public-Key Encryption

```javascript
const { 
    Asymmetric, 
    AsymmetricSecretKey
} = require('dhole-crypto');

(async function () {
    let foxSecret = await AsymmetricSecretKey.generate();
    let foxPublic = foxSecret.getPublicKey();
    
    let wolfSecret = await AsymmetricSecretKey.generate();
    let wolfPublic = wolfSecret.getPublicKey();
    
    let message = "Encrypt me UwU";
    let encrypted = await Asymmetric.encrypt(message, foxPublic, wolfSecret);
    let decrypted = await Asymmetric.decrypt(encrypted, foxSecret, wolfPublic);
    console.log(decrypted.toString()); // "Encrypt me UwU"
})();
```

#### Anonymous Public-Key Encryption

```javascript
const { 
    Asymmetric, 
    AsymmetricSecretKey
} = require('dhole-crypto');

(async function () {
    let foxSecret = await AsymmetricSecretKey.generate();
    let foxPublic = foxSecret.getPublicKey();
    
    let message = "Encrypt me UwU";
    let encrypted = await Asymmetric.seal(message, foxPublic);
    let decrypted = await Asymmetric.unseal(encrypted, foxSecret);
    console.log(decrypted.toString()); // "Encrypt me UwU"
})();
```

### Symmetric Cryptography

#### Encryption

```javascript
const {
    Symmetric,
    SymmetricKey
} = require('dhole-crypto');

(async function () {
let symmetricKey = await SymmetricKey.generate();

let message = "Encrypt me UwU";
let encrypted = await Symmetric.encrypt(message, symmetricKey);
let decrypted = await Symmetric.decrypt(encrypted, symmetricKey);
console.log(decrypted); // "Encrypt me UwU"
})();
```

#### Encryption with Additional Data 

```javascript
const {
    Symmetric,
    SymmetricKey
} = require('dhole-crypto');

(async function () {
    let symmetricKey = await SymmetricKey.generate();
    
    let message = "Encrypt me UwU";
    let publicData = "OwO? UwU";
    let encrypted = await Symmetric.encryptWithAd(message, symmetricKey, publicData);
    let decrypted = await Symmetric.decryptWithAd(encrypted, symmetricKey, publicData);
    console.log(decrypted); // "Encrypt me UwU"
})();
```

#### Unencrypted Message Authentication

```javascript
const {
    Symmetric,
    SymmetricKey
} = require('dhole-crypto');

(async function () {
    let symmetricKey = await SymmetricKey.generate();
    
    let message = "AWOOOOOOOOOOOO";
    let mac = await Symmetric.auth(message, symmetricKey);
    if (!await Symmetric.verify(message, mac, symmetricKey)) {
        console.log("Unauthorized Awoo. $350 fine incoming");
    }
})();
```

## Password Storage

```javascript
const {
    Password,
    SymmetricKey
} = require('dhole-crypto');

(async function () {
    let symmetricKey = await SymmetricKey.generate();
    let pwHandler = new Password(symmetricKey);
    
    let password = 'cowwect howse battewy staple UwU';
    let pwhash = await pwHandler.hash(password);
    if (!await pwHandler.verify(password, pwhash)) {
        console.log("access denied");    
    }
})();
```

## Keyring

You can serialize any key by using the `Keyring` class.

```javascript
const {
    AsymmetricSecretKey,
    Keyring,
    SymmetricKey
} = require('dhole-crypto');

(async function () {
    let foxSecret = await AsymmetricSecretKey.generate();
    let foxPublic = foxSecret.getPublicKey();
    let symmetric = await SymmetricKey.generate();
    // Load a serializer
    let ring = new Keyring();
    
    // Serialize to string
    let sk = await ring.save(foxSecret);
    let pk = await ring.save(foxPublic);
    let key = await ring.save(symmetric);
    
    // Load from string
    let loadSk = await ring.load(sk);
    let loadPk = await ring.load(pk);
    let loadSym = await ring.load(key);
})();
```

The `Keyring` class also supports keywrap. Simply pass a separate `SymmetricKey`
instance to the constructor to get wrapped keys.

```javascript
const {
    AsymmetricSecretKey,
    Keyring,
    SymmetricKey
} = require('dhole-crypto');

(async function () {
    // Keywrap key...
    let wrap = await SymemtricKey.generate();
    
    let foxSecret = await AsymmetricSecretKey.generate();
    let foxPublic = foxSecret.getPublicKey();
    let symmetric = await SymmetricKey.generate();
    
    // Load a serializer
    let ring = new Keyring(wrap);
    
    // Serialize to string
    let sk = await ring.save(foxSecret);
    let pk = await ring.save(foxPublic);
    let key = await ring.save(symmetric);
    
    // Load from string
    let loadSk = await ring.load(sk);
    let loadPk = await ring.load(pk);
    let loadSym = await ring.load(key);
})();
```

# Support

If you run into any trouble using this library, or something breaks,
feel free to file a Github issue.

If you need help with integration, [Soatok is available for freelance work](https://soatok.com/freelance).
