const keyUsages = Object.freeze(['deriveKey', 'deriveBits']);
const algorithm = Object.freeze({
    name: 'ECDH',
    namedCurve: 'P-256',
}); 
const format = 'jwk';

export default class Be8 {
    async generatePrivAndPubKey () {
        return window.crypto.subtle.generateKey(algorithm, true, keyUsages).then(function ({ privateKey, publicKey }) {
            const proms = [
                window.crypto.subtle.exportKey(format, publicKey),
                window.crypto.subtle.exportKey(format, privateKey)
            ];
        
            return Promise.all(proms);
        });
    }
}