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
};
connection.onerror = function (event) {
    console.log(event);
};

export default connection;