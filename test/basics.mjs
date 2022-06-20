import database from './database.mjs';
import Be8 from './bundle.mjs';

QUnit.module('Basics');

QUnit.test('Check if keys are generated', async function (assert) {
    const be8 = new Be8('10', database);
    
    await be8.generatePrivAndPubKey();
    return assert.equal(be8.hasKeys(), true, 'Be8 object returns keys.');
});

QUnit.test('Get cached keys from db', async function (assert) {
    const be8Sender = new Be8('11', database);
    const be8Receiver = new Be8('12', database);
    const [publicKey] = await be8Sender.generatePrivAndPubKey();

    be8Receiver.addPublicKey('11', publicKey);
    const keys = await be8Receiver.getCachedKeys();
    
    keys.forEach(function ({ accID, publicKey }) {
        console.log(publicKey);
        assert.equal(typeof publicKey, 'object', 'is a string id');
        return assert.equal(!isNaN(accID), true, 'is a string id');
    });
});


export default {};
