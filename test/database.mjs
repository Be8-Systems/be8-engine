// we confige the db outside of the module
// therefore we are not coupled to the module database requirements
// maybe we want to store more which is not related to the engine itself
const connection = indexedDB.open('be8', 5);

connection.onupgradeneeded = function () {
    const db = connection.result;
    const publicKeysStore = db.createObjectStore('publicKeys', { keyPath: 'accID' });

    publicKeysStore.createIndex('crv', 'crv', { unique: false });
    publicKeysStore.createIndex('ext', 'ext', { unique: false });
    publicKeysStore.createIndex('key_ops', 'key_ops', { unique: false });
    publicKeysStore.createIndex('kty', 'kty', { unique: false });
    publicKeysStore.createIndex('x', 'x', { unique: false });
    publicKeysStore.createIndex('y', 'y', { unique: false });

    const privateKeysStore = db.createObjectStore('privateKeys', { keyPath: 'accID' });

    privateKeysStore.createIndex('crv', 'crv', { unique: false });
    privateKeysStore.createIndex('ext', 'ext', { unique: false });
    privateKeysStore.createIndex('key_ops', 'key_ops', { unique: false });
    privateKeysStore.createIndex('kty', 'kty', { unique: false });
    privateKeysStore.createIndex('x', 'x', { unique: false });
    privateKeysStore.createIndex('y', 'y', { unique: false });
};
connection.onerror = function (event) {
    console.log(event);
};

export default connection;