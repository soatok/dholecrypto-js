# DholeCrypto.js

[![Travis CI](https://travis-ci.org/soatok/dholecrypto-js.svg?branch=master)](https://travis-ci.org/soatok/dholecrypto-js)
[![npm version](https://img.shields.io/npm/v/dhole-crypto.svg)](https://npm.im/dhole-crypto)

JavaScript port of [Dhole Cryptography](https://github.com/soatok/dhole-cryptography) (PHP).

Libsodium wrapper for Soatok's JavaScript projects. Released under the very
permissive ISC license.

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

let wolfSecret = AsymmetricSecretKey.generate();
let wolfPublic = wolfSecret.getPublicKey();

let message = "Your $350 awoo fine has been paid UwU";

let signature = Asymmetric.sign(message, wolfSecret);

if (!Asymmetric.verify(message, wolfPublic, signature)) {
    console.log("Invalid signature. Awoo not authorized.");
}
```

#### Authenticated Public-Key Encryption

```javascript
const { 
    Asymmetric, 
    AsymmetricSecretKey
} = require('dhole-crypto');

let foxSecret = AsymmetricSecretKey.generate();
let foxPublic = foxSecret.getPublicKey();

let wolfSecret = AsymmetricSecretKey.generate();
let wolfPublic = wolfSecret.getPublicKey();

let message = "Encrypt me UwU";
let encrypted = Asymmetric.encrypt(message, foxPublic, wolfSecret);
let decrypted = Asymmetric.decrypt(encrypted, foxSecret, wolfPublic);
console.log(decrypted); // "Encrypt me UwU"
```

#### Anonymous Public-Key Encryption

```javascript
const { 
    Asymmetric, 
    AsymmetricSecretKey
} = require('dhole-crypto');

let foxSecret = AsymmetricSecretKey.generate();
let foxPublic = foxSecret.getPublicKey();

let message = "Encrypt me UwU";
let encrypted = Asymmetric.seal(message, foxPublic);
let decrypted = Asymmetric.unseal(encrypted, foxSecret);
console.log(decrypted); // "Encrypt me UwU"
```

### Symmetric Cryptography

#### Encryption

```javascript
const {
    Symmetric,
    SymmetricKey
} = require('dhole-crypto');

let symmetricKey = SymmetricKey.generate();

let message = "Encrypt me UwU";
let encrypted = Symmetric.encrypt(message, symmetricKey);
let decrypted = Symmetric.decrypt(encrypted, symmetricKey);
console.log(decrypted); // "Encrypt me UwU"
```

#### Encryption with Additional Data 

```javascript
const {
    Symmetric,
    SymmetricKey
} = require('dhole-crypto');

let symmetricKey = SymmetricKey.generate();

let message = "Encrypt me UwU";
let publicData = "OwO? UwU";
let encrypted = Symmetric.encryptWithAd(message, symmetricKey, publicData);
let decrypted = Symmetric.decryptWithAd(encrypted, symmetricKey, publicData);
console.log(decrypted); // "Encrypt me UwU"
```

#### Unencrypted Message Authentication

```javascript
const {
    Symmetric,
    SymmetricKey
} = require('dhole-crypto');

let symmetricKey = SymmetricKey.generate();

let message = "AWOOOOOOOOOOOO";
let mac = Symmetric.auth(message, symmetricKey);
if (!Symmetric.verify(message, mac, symmetricKey)) {
    console.log("Unauthorized Awoo. $350 fine incoming");
}
```

## Password Storage

```javascript
const {
    Password,
    SymmetricKey
} = require('dhole-crypto');

let symmetricKey = SymmetricKey.generate();
let pwHandler = new Password(symmetricKey);

let password = 'cowwect howse battewy staple UwU';
let pwhash = pwHandler.hash(password);
if (!pwHandler.verify(password, pwhash)) {
    console.log("access denied");    
}
```

## Keyring

You can serialize any key by using the `Keyring` class.

```javascript
const {
    AsymmetricSecretKey,
    Keyring,
    SymmetricKey
} = require('dhole-crypto');

let foxSecret = AsymmetricSecretKey.generate();
let foxPublic = foxSecret.getPublicKey();
let symmetric = SymmetricKey.generate();
// Load a serializer
let ring = new Keyring(wrap);

// Serialize to string
let sk = ring.save(foxSecret);
let pk = ring.save(foxPublic);
let key = ring.save(symmetric);

// Load from string
let loadSk = ring.load(sk);
let loadPk = ring.load(pk);
let loadSym = ring.load(key);
```

The `Keyring` class also supports keywrap. Simply pass a separate `SymmetricKey`
instance to the constructor to get wrapped keys.

```javascript
const {
    AsymmetricSecretKey,
    Keyring,
    SymmetricKey
} = require('dhole-crypto');

// Keywrap key...
let wrap = SymemtricKey.generate();

let foxSecret = AsymmetricSecretKey.generate();
let foxPublic = foxSecret.getPublicKey();
let symmetric = SymmetricKey.generate();

// Load a serializer
let ring = new Keyring(wrap);

// Serialize to string
let sk = ring.save(foxSecret);
let pk = ring.save(foxPublic);
let key = ring.save(symmetric);

// Load from string
let loadSk = ring.load(sk);
let loadPk = ring.load(pk);
let loadSym = ring.load(key);
```

# Support

If you run into any trouble using this library, or something breaks,
feel free to file a Github issue.

If you need help with integration, [Soatok is available for freelance work](https://soatok.com/freelance).
