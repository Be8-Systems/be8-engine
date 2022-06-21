// we confige the db outside of the module
// therefore we are not coupled to the module database requirements
// maybe we want to store more which is not related to the engine itself
const connection = indexedDB.open('be8', 1);

connection.onupgradeneeded = function () {
    const db = connection.result;
    const publicKeysStore = db.createObjectStore('publicKeys', { keyPath: 'accID' });
    const privateKeysStore = db.createObjectStore('privateKeys', { keyPath: 'accID' });
    const indexs = [
        ['crv', 'crv', { unique: false }],
        ['x', 'x', { unique: false }],
        ['y', 'y', { unique: false }],
        ['kty', 'kty', { unique: false }],
        ['key_ops', 'key_ops', { unique: false }],
        ['ext', 'ext', { unique: false }],
    ];

    indexs.forEach(function (parameters) {
        publicKeysStore.createIndex(...parameters);
        privateKeysStore.createIndex(...parameters);
    });
};

connection.onerror = function (event) {
    console.log(event);
};

export default connection;