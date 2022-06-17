import { generateIV, arrayBufferToBase64, getTypeOfKey } from './util.mjs';

const keyUsages = Object.freeze(['deriveKey', 'deriveBits']);
const algorithmType = 'ECDH'; // Elliptic Curve Diffie-Hellman
const algorithm = Object.freeze({
    name: algorithmType, 
    namedCurve: 'P-384', // 384-bit prime curve
}); 
const format = 'jwk'; // json web key format

export default class Be8 {
    #accID = '';
    #publicKeys = new Map();
    #privateKeys = new Map();
    #groupKeys = new Map();
    #channelKeys = new Map();

    constructor (accID) {
        const hasPrivkey = localStorage.getItem('privateKey');
        const hasPubKey = localStorage.getItem('publicKey');
        const storedAccID = localStorage.getItem('accID');

        this.#accID = accID;
        
        if (typeof accID !== 'string' && !isNaN('1')) {
            throw `no acc id or wrong type passed to the constructor got ${accID}`;
        }

        if (storedAccID !== accID) {
            console.log('new acc or first time');
        } else {
            console.log('old acc');

            if (hasPrivkey && hasPubKey) {
                this.#publicKeys.set(accID, JSON.parse(hasPubKey));
                this.#privateKeys.set(accID, JSON.parse(hasPrivkey));
            } else {
                console.log('old acc but no keys');
            }
        }
    }

    hasKeys () {
        const publicKey = this.#publicKeys.has(this.#accID);
        const privatekey = this.#privateKeys.has(this.#accID);

        if (!publicKey) {
            console.log(`No public key for ${this.#accID} in hasKeys`);
        }
        if (!privatekey) {
            console.log(`No private key for ${this.#accID} in hasKeys`);
        }

        return publicKey && privatekey;
    }

    #getKey (id) {
        const type = getTypeOfKey(id);

        if (type === 'group') {
            return this.#groupKeys.get(id);
        }
        if (type === 'channel') {
            return this.#channelKeys.get(id);
        }

        return this.#publicKeys.get(id);
    } 

    addPublicKeys (publicKeys = []) {
        publicKeys.forEach(({ accID, publicKey }) => this.#publicKeys.set(accID, publicKey));
    }

    addPublicKey (accID, key) {
        if (!accID) {
            console.log(`missing accID: "${accID}" at addPublicKey`);
        }
        if (!key) {
            console.log(`missing key: "${key}" at addPublicKey`);
        }
       
        return this.#publicKeys.set(accID, key);
    }

    addGroupKey (groupID, key) {
        if (groupID && key) {
            this.#groupKeys.set(groupID, key);
        } else {
            console.log(`missing accID: "${groupID}" or key: "${key}" in addGroupKey`);
        }
    }

    async generatePrivAndPubKey () {
        const { privateKey, publicKey } = await window.crypto.subtle.generateKey(algorithm, true, keyUsages);
        const proms = [
            window.crypto.subtle.exportKey(format, publicKey),
            window.crypto.subtle.exportKey(format, privateKey)
        ];
        const keys = await Promise.all(proms);

        this.#publicKeys.set(this.#accID, keys[0]);
        this.#privateKeys.set(this.#accID, keys[1]);
        
        return keys;
    }

    async encryptTextSimple (accIDSender, accIDReceiver, text) {
        const publicKey = this.#getKey(accIDReceiver);
        const privateKey = this.#privateKeys.get(accIDSender);

        if (!publicKey) {
            throw `Missing public key for ${accIDReceiver} at encryptTextSimple`;
        }
        if (!privateKey) {
            throw `Missing private key for ${accIDSender} at encryptTextSimple`;
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.encryptText(derivedKey, text);
    }

    async decryptTextSimple (accIDSender, accIDReceiver, cipherText, iv) {
        const publicKey = this.#getKey(accIDSender);
        const privateKey = this.#privateKeys.get(accIDReceiver);

        if (!publicKey) {
            throw `Missing public key for ${accIDSender} at decryptTextSimple`;
        }
        if (!privateKey) {
            throw `Missing private key for ${accIDReceiver} at decryptTextSimple`;
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.decryptText(derivedKey, cipherText, iv);
    }

    async getDerivedKey (publicKey, privateKey) {
        if (!publicKey) {
            throw 'no public key passed to getDerivedKey';
        }
        if (!privateKey) {
            throw 'no private key passed to getDerivedKey';
        }
        
        const publicKeyProm = window.crypto.subtle.importKey(format, publicKey, algorithm, true, []);
        const privateKeyProm = window.crypto.subtle.importKey(format, privateKey, algorithm, true, keyUsages);
    
        return Promise.all([publicKeyProm, privateKeyProm]).then(function ([publicKey, privateKey]) {
            const algorithm = { 
                name: 'AES-GCM', // Advanced Encryption Standard Galois/Counter Mode 
                length: 256 
            };

            return window.crypto.subtle.deriveKey({ name: algorithmType, public: publicKey }, privateKey, algorithm, true, ['encrypt', 'decrypt']);
        });
    }

    async encryptText (derivedKey, text = '') {
        const encodedText = new TextEncoder().encode(text);
        const iv = generateIV();
        const algorithm = { 
            name: 'AES-GCM', 
            iv
        };

        if (!derivedKey) {
            throw 'no derived key passed to encryptText';
        }
    
        return window.crypto.subtle.encrypt(algorithm, derivedKey, encodedText).then(function (encryptedData) {
            const uintArray = new Uint8Array(encryptedData);
            const string = String.fromCharCode.apply(null, uintArray);
            const cipherText = window.btoa(string);
          
            return { cipherText, iv };
        });
    }

    async decryptText (derivedKey, cipherText, iv) {
        const mstring = window.atob(cipherText);
        const uintArray = new Uint8Array([...mstring].map((char) => char.charCodeAt(0)));
        const algorithm = {
            name: 'AES-GCM',
            iv,
        };

        if (!derivedKey) {
            throw 'no derived key passed to decryptText';
        }
        if (!iv) {
            throw 'no iv (Initialization vector) passed to decryptText';
        }
    
        return window.crypto.subtle.decrypt(algorithm, derivedKey, uintArray).then(function (decryptedData) {
            return new TextDecoder().decode(decryptedData);
        });
    }

    // not tested yet
    async encryptImage (derivedKey, base64Image) {
        const encodedText = new TextEncoder().encode(base64Image);
        const iv = generateIV();

        if (!derivedKey) {
            throw 'no derived key passed to decryptText';
        }
    
        return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, derivedKey, encodedText).then(function (encryptedData) {
            return {
                cipherImage: arrayBufferToBase64(encryptedData),
                iv
            };
        });
    }

    // not tested yet
    async decryptImage (derivedKey, cipherImage, iv) {
        const mstring = window.atob(cipherImage);
        const uintArray = new Uint8Array([...mstring].map((char) => char.charCodeAt(0)));
        const algorithm = {
            name: 'AES-GCM',
            iv,
        };

        if (!derivedKey) {
            throw 'no derived key passed to decryptText';
        }
    
        return window.crypto.subtle.decrypt(algorithm, derivedKey, uintArray).then(function (decryptedData) {
            return new TextDecoder().decode(decryptedData);
        });
    }
}