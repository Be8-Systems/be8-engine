# be8-engine
Be8 uses a Elliptic Curve Diffie-Hellman 384 bit prime curve encryption to ensure
safe e2ee communications.

## usage
The constructer takes one parameter the accID. 
In case of no id passed it throws an error. ID has to be
a string that is a number.

```javascript
const be8 = new Be8('1');
```

## hasKeys()

Checks if the object already generated keys and if they are stored.
Returns a boolean.

```javascript
be8.hasKeys();
```

## addPublicKeys (publicKeys = [])
Takes an array of public key accid key pair values and calls addPublicKey for every pair. 

```javascript 
const publicKeys = [{
    accID: '',
    publicKey: {
        crv: 'P-384'
        ext: 'true'
        key_ops: ['deriveKey', 'deriveBits']
        kty: 'EC'
        x: 'A8QYrJJeE5iEshV3ycX2DNvgltSq9NHQypmkDybLHII'
        y: 'IxbSJxIfvjuBvyTlNt_RToCgYzqvBHsIvWVB8bW-EFs'
    }
}]; 

be8.addPublicKeys(publicKeys);
```

## addPublicKey(accID, key)
Adds an accID publicKey pair value to a private map.

```javascript
const publicKey = {
    accID: '10101',
    publicKey: {
        crv: 'P-384'
        ext: 'true'
        key_ops: ['deriveKey', 'deriveBits']
        kty: 'EC'
        x: 'A8QYrJJeE5iEshV3ycX2DNvgltSq9NHQypmkDybLHII'
        y: 'IxbSJxIfvjuBvyTlNt_RToCgYzqvBHsIvWVB8bW-EFs'
    }
};

be8.addPublicKey(publicKey);
```

## addGroupKey(groupID, key)
Group keys are stored seperately from the other keys.

```javascript
be8.addGroupKey('g10300', {});
```

## async generatePrivAndPubKey()
Returns freshly generated private and public keys. Automatically stores the keys in the localstorage.

```javascript
const [publicKey, privateKey] = await be8.generatePrivAndPubKey();
```

## async getDerivedKey(publicKey, privateKey)
Generates a derived key out of the public and private key. 

```javascript
const privateKey = {};
const publicKey = {};
const derivedKey = await be8.getDerivedKey(publicKey, privateKey);
```

## async encryptText(derivedKey, text = '')
After creating a [derivedKey](#async-getderivedkeypublickeyjwk-privatekeyjwk) we can start to encrypt text messages. encryptText returns a cipherText and a iv (Initialization vector).
 
```javascript
const text = 'Hello World';
const derivedKey = await be8.getDerivedKey(publicKey, privateKey);
const { cipherText, iv } = await be8.encryptText(derivedKey, text);
```

## async decryptText(derivedKey, cipherText, iv)
With the help of the key, the cipherText and an iv, we can decrypt messages.

```javascript
const cipherText = 'ASDASD9324/&§$jn';
const iv = '213210931249713409';
const derivedKey = await be8.getDerivedKey(publicKey, privateKey);
const text = await be8.decryptText(derivedKey, cipherText);
```

## encryptTextSimple(accIDSender, accIDReceiver, text)
encryptTextSimple is a compound function of [encryptText](#async-encrypttextderivedkey-text) and [getDerivedKey](#async-getderivedkeypublickey-privatekey). It uses the ids instead of keys. 
The derivedKey is generated inside the function.

```javascript
const accIDSender = '101010';
const accIDReceiver = '101011';
const text = 'Hello World';
const cipherText = await be8.encryptTextSimple(accIDSender, accIDReceiver, text);
```

## async decryptTextSimple(accIDSender, accIDReceiver, cipherText, iv)
decryptTextSimple is a compound function of [decryptText](#async-decrypttextderivedkey-text) and [getDerivedKey](#async-getderivedkeypublickey-privatekey). It uses the ids instead of keys. 
The derivedKey is generated inside the function.

```javascript
const accIDSender = '101010';
const accIDReceiver = '101011';
const cipherText = 'sadadwWE=)AWLKASDS';
const iv = '2139484765456789';
const cipherText = await be8.decryptTextSimple(accIDSender, accIDReceiver, cipherText, iv);
```

## async encryptImage(derivedKey, base64Image)
Accepts the derivedKey and an image encoded as base64 so it can creates a "cipherImage" and 
an iv.

```javascript
const { cipherImage, iv } = await be8.encryptImage(derivedKey, base64Image);
```

## async decryptImage(derivedKey, cipherImage, iv)
Uses the derivedKey, the cipherImage and the iv to decrypt a base64Image.

```javascript
const base64Image = await be8.encryptImage(derivedKey, cipherImage, iv);
```

## Scripts
### building
Rollup creates two versions one is a esm6 version and a minified iife one.
Both can be found in /dist.

```bash
npm run build
```

### Testing 
Open http://localhost:3000/ in your browser to see the 
qunit suite.

```bash
npm test
```