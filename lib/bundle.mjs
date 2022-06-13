const keyUsages = Object.freeze(['deriveKey', 'deriveBits']);
const algorithmType = 'ECDH'; // Elliptic Curve Diffie-Hellman
const algorithm = Object.freeze({
    name: algorithmType, 
    namedCurve: 'P-256', // 256-bit prime curve
}); 
const format = 'jwk'; // json web key format

function generateIV () {
    return window.crypto.getRandomValues(new Uint8Array(16)).join('');
}

function _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return window.btoa(binary);
}

export default class Be8 {
    #accID = '';

    constructor (accID) {
        this.#accID = accID;
    }

    async generatePrivAndPubKey () {
        return window.crypto.subtle.generateKey(algorithm, true, keyUsages).then(function ({ privateKey, publicKey }) {
            const proms = [
                window.crypto.subtle.exportKey(format, publicKey),
                window.crypto.subtle.exportKey(format, privateKey)
            ];
        
            return Promise.all(proms);
        });
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
            iv: new TextEncoder().encode(iv) 
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
            iv: new TextEncoder().encode(iv),
        };
    
        return window.crypto.subtle.decrypt(algorithm, derivedKey, uintArray).then(function (decryptedData) {
            return new TextDecoder().decode(decryptedData);
        });
    }

    async encryptImage  (derivedKey, image) {
        const encodedText = new TextEncoder().encode(image);
    
        return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: new TextEncoder().encode(generateIV()) }, derivedKey, encodedText).then(function (encryptedData) {
            return _arrayBufferToBase64(encryptedData);
        });
    }

    async decryptImage (derivedKey, encryptedMsg) {
        const mstring = window.atob(encryptedMsg);
        const uintArray = new Uint8Array([...mstring].map((char) => char.charCodeAt(0)));
        const algorithm = {
            name: 'AES-GCM',
            iv: new TextEncoder().encode(generateIV()),
        };
    
        return window.crypto.subtle.decrypt(algorithm, derivedKey, uintArray).then(function (decryptedData) {
            return new TextDecoder().decode(decryptedData);
        });
    }
}