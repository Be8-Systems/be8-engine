// generates an Initialization vector
export function generateIV () {
    // a nonce (number once) is an arbitrary number that can be used just once in a cryptographic communication
    const nonce = window.crypto.getRandomValues(new Uint8Array(16)).join('');
    return new TextEncoder().encode(nonce);
}

export function arrayBufferToBase64 (buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return window.btoa(binary);
}