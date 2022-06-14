import { generateIV, arrayBufferToBase64 } from './util.mjs';

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

    constructor (accID) {
        const hasPrivkey = localStorage.getItem('privateKey');
        const hasPubKey = localStorage.getItem('publicKey');
        const storedAccID = localStorage.getItem('accID');

        this.#accID = accID;

        if (storedAccID !== accID) {
            console.log('new acc or first time');
        } else {
            console.log('old acc');

            if (hasPrivkey && hasPubKey) {
                this.#publicKeys.set(accID, JSON.parse(hasPubKey));
                this.#privateKeys.set(accID, JSON.parse(hasPrivkey));
            } else {
                console.log('old keys but no keys');
            }
        }
    }

    hasKeys () {
        return this.#publicKeys.has(this.#accID) && this.#privateKeys.has(this.#accID);
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

    async _encryptText (accIDSender, accIDReceiver, text) {
        const publicKey = this.#publicKeys.get(accIDReceiver);
        const privateKey = this.#privateKeys.get(accIDSender);
        const key = await this.getDerivedKey(publicKey, privateKey);

        return await this.encryptText(key, text);
    }

    async getDerivedKey (publicKeyJwk, privateKeyJwk) {
        const publicKey = window.crypto.subtle.importKey(format, publicKeyJwk, algorithm, true, []);
        const privateKey = window.crypto.subtle.importKey(format, privateKeyJwk, algorithm, true, keyUsages);
    
        return Promise.all([publicKey, privateKey]).then(function ([publicKey, privateKey]) {
            const algorithm = { 
                name: 'AES-GCM', // Advanced Encryption Standard Galois/Counter Mode 
                length: 256 
            };

            return window.crypto.subtle.deriveKey({ name: algorithmType, public: publicKey }, privateKey, algorithm, true, ['encrypt', 'decrypt']);
        });
    }

    async encryptText (derivedKey, text) {
        const encodedText = new TextEncoder().encode(text);
        const iv = generateIV();
        const algorithm = { 
            name: 'AES-GCM', 
            iv
        };
    
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
    
        return window.crypto.subtle.decrypt(algorithm, derivedKey, uintArray).then(function (decryptedData) {
            return new TextDecoder().decode(decryptedData);
        });
    }

    async encryptImage  (derivedKey, image) {
        const encodedText = new TextEncoder().encode(image);
    
        return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: generateIV() }, derivedKey, encodedText).then(function (encryptedData) {
            return arrayBufferToBase64(encryptedData);
        });
    }

    async decryptImage (derivedKey, encryptedMsg) {
        const mstring = window.atob(encryptedMsg);
        const uintArray = new Uint8Array([...mstring].map((char) => char.charCodeAt(0)));
        const algorithm = {
            name: 'AES-GCM',
            iv: generateIV(),
        };
    
        return window.crypto.subtle.decrypt(algorithm, derivedKey, uintArray).then(function (decryptedData) {
            return new TextDecoder().decode(decryptedData);
        });
    }
}