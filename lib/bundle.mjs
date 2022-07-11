import { generateIV, arrayBufferToBase64, getTypeOfKey } from './util.mjs';

const keyUsages = Object.freeze(['deriveKey', 'deriveBits']);
const algorithmType = 'ECDH'; // Elliptic Curve Diffie-Hellman
const algorithm = Object.freeze({
    name: algorithmType, 
    namedCurve: 'P-384', // 384-bit prime curve
}); 
const format = 'jwk'; // json web key format

export default class Be8 {
    #indexedDB = {};
    #accID = '';
    #publicKeys = new Map();
    #privateKeys = new Map();
    #groupKeys = new Map();
    #channelKeys = new Map();

    constructor (accID, indexedDB) {
        this.#accID = accID;
        this.#indexedDB = indexedDB;

        if (typeof accID !== 'string' || isNaN(accID)) {
            throw `no acc id or wrong type passed to the constructor got ${accID}`;
        }
        if (!indexedDB) {
            throw 'no indexedDB passed to the constructor';
        }
    }

    async setup () {
        const databaseKeys = await this.getCachedKeys();
        const privateTx = this.#indexedDB.result.transaction('privateKeys', 'readwrite');
        const privateKeysStore = privateTx.objectStore('privateKeys');
        const all = privateKeysStore.getAll(); 
        const newAccID = this.#accID;
        const privateKey = await new Promise(function (success) {
            all.onsuccess = function (event) {
                return success(event.target.result.find(key => key.accID === newAccID));
            };
        });

        if (!privateKey) { 
            console.log('brand new acc');
            await this.generatePrivAndPubKey();
        } else {
            console.log('old acc');
            this.#privateKeys.set(this.#accID, privateKey);
        }

        databaseKeys.forEach(({ accID, publicKey }) => this.#publicKeys.set(accID, publicKey));
        
        return databaseKeys; 
    }

    getAccID () {
        return this.#accID;
    }

    hasGeneratedKeys () {
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

    async addPublicKeys (publicKeys = []) {
        const tx = this.#indexedDB.result.transaction('publicKeys', 'readwrite');
        const publicKeysStore = tx.objectStore('publicKeys');
        
        publicKeys.forEach(({ accID, publicKey }) => this.#publicKeys.set(accID, publicKey)); 
        const proms = publicKeys.map(function ({ accID, publicKey }) {
            publicKeysStore.put({ accID, ...publicKey });
            publicKeysStore.onsuccess = () => console.log(`added public key for ${accID}`);
        });

        return await Promise.all(proms);
    }

    addPublicKey (accID, key) {
        const tx = this.#indexedDB.result.transaction('publicKeys', 'readwrite');
        const publicKeysStore = tx.objectStore('publicKeys');

        if (!accID) {
            console.log(`missing accID: "${accID}" at addPublicKey`);
        }
        if (!key) {
            console.log(`missing key: "${key}" at addPublicKey`);
        }
       
        publicKeysStore.put({ accID, ...key });
        return this.#publicKeys.set(accID, key);
    }

    async addGroupKeys (groupID, groupKeys) {
        if (groupID && groupKeys?.length > 0) {
            const tx = this.#indexedDB.result.transaction('groupKeys', 'readwrite');
            const groupKeysStore = tx.objectStore('groupKeys');

            groupKeys.forEach(({ version, groupKey }) => this.#groupKeys.set(`${groupID}:${version}`, groupKey));
            const proms = groupKeys.map(function ({ version, groupKey }) {
                console.log(groupID, version, ...groupKey);
                groupKeysStore.put({ groupID, version, ...groupKey });
                groupKeysStore.onsuccess = () => console.log(`added group key for ${groupID}`);
            });
    
            return await Promise.all(proms);
        } else {
            console.log(`missing groupID: "${groupID}" or keys: "${groupKeys}" in addGroupKey`);
        }
    }

    async getCachedKeys () {
        const tx = this.#indexedDB.result.transaction('publicKeys', 'readwrite');
        const publicKeysStore = tx.objectStore('publicKeys');
        const all = publicKeysStore.getAll(); 

        return await new Promise(function (success) {
            all.onsuccess = function (event) {
                const keys = event.target.result.map(key => ({ accID: key.accID, publicKey: key }));
                return success(keys);
            };
        });
    }

    async generateGroupKeys (version) {
        const { privateKey, publicKey } = await window.crypto.subtle.generateKey(algorithm, true, keyUsages);
        const proms = [
            window.crypto.subtle.exportKey(format, publicKey),
            window.crypto.subtle.exportKey(format, privateKey)
        ];
        const keys = await Promise.all(proms);
        const hasKeys = this.#groupKeys.get(version);

        if (hasKeys) {
            console.log(`Group keys for ${version} already exist`);
            return hasKeys;
        }
        
        this.#groupKeys.set(version, keys[1]);
            
        return keys;
    }

    async generatePrivAndPubKey () {
        const { privateKey, publicKey } = await window.crypto.subtle.generateKey(algorithm, true, keyUsages);
        const proms = [
            window.crypto.subtle.exportKey(format, publicKey),
            window.crypto.subtle.exportKey(format, privateKey)
        ];
        const keys = await Promise.all(proms);
        const privateTx = this.#indexedDB.result.transaction('privateKeys', 'readwrite');
        const publicTX = this.#indexedDB.result.transaction('publicKeys', 'readwrite');
        const publicKeysStore = publicTX.objectStore('publicKeys');
        const privateKeysStore = privateTx.objectStore('privateKeys');

        publicKeysStore.put({ accID: this.#accID, ...keys[0] });
        privateKeysStore.put({ accID: this.#accID, ...keys[1] });
        this.#publicKeys.set(this.#accID, keys[0]);
        this.#privateKeys.set(this.#accID, keys[1]);

        await privateTx.complete;
        await publicTX.complete;

        return keys;
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
        const stringifiedIV = new TextDecoder().decode(iv);
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
          
            return { cipherText, iv: stringifiedIV };
        });
    }

    async decryptText (derivedKey, cipherText = '', iv) {
        const mstring = window.atob(cipherText);
        const uintArray = new Uint8Array([...mstring].map((char) => char.charCodeAt(0)));
        const parsedIV = new TextEncoder('utf-8').encode(iv);
        const algorithm = {
            name: 'AES-GCM',
            iv: parsedIV,
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

    async encryptImageSimple (accIDSender, accIDReceiver, base64Image) {
        const publicKey = this.#getKey(accIDReceiver);
        const privateKey = this.#privateKeys.get(accIDSender);
        
        if (!publicKey) {
            throw `Missing public key for ${accIDSender} at encryptImageSimple`;
        }
        if (!privateKey) {
            throw `Missing private key for ${accIDReceiver} at encryptImageSimple`;
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);
        
        return await this.encryptImage(derivedKey, base64Image);
    }

    async decryptImageSimple (accIDSender, accIDReceiver, cipherImage, iv) {
        const publicKey = this.#getKey(accIDSender);
        const privateKey = this.#privateKeys.get(accIDReceiver);
        
        if (!publicKey) {
            throw `Missing public key for ${accIDSender} at decryptImageSimple`;
        }
        if (!privateKey) {
            throw `Missing private key for ${accIDReceiver} at decryptImageSimple`;
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.decryptImage(derivedKey, cipherImage, iv);
    }

    async panic () {
        const pubKeys = [...this.#publicKeys.keys()];
        const privKeys = [...this.#privateKeys.keys()];
        const groupKeys = [...this.#groupKeys.keys()];
        const pubtx = this.#indexedDB.result.transaction('publicKeys', 'readwrite');
        const privtx = this.#indexedDB.result.transaction('privateKeys', 'readwrite');
        const grouptx = this.#indexedDB.result.transaction('groupKeys', 'readwrite');
        const publicKeysStore = pubtx.objectStore('publicKeys');
        const privateKeysStore = privtx.objectStore('privateKeys');
        const groupKeysStore = grouptx.objectStore('groupKeys');
        
        const pubKeyProms = pubKeys.map(function (key) {
            return new Promise(function (resolve) {
                publicKeysStore.delete(key);
                return resolve();
            });
        });
        const privKeyProms = privKeys.map(function (key) {
            return new Promise(function (resolve) {
                privateKeysStore.delete(key);
                return resolve();
            });
        });
        const groupKeyProms = groupKeys.map(function (key) {
            return new Promise(function (resolve) {
                groupKeysStore.delete(key);
                return resolve();
            });
        });

        await Promise.all([...pubKeyProms, ...privKeyProms, ...groupKeyProms]);

        this.#publicKeys.clear();
        this.#privateKeys.clear();
        this.#groupKeys.clear();
        this.#channelKeys.clear();
    }
}