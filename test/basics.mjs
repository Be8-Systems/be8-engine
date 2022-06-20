import database from './database.mjs';
import Be8 from './bundle.mjs';

QUnit.module('Basics');

QUnit.test('Check if keys are generated', async function (assert) {
    const be8 = new Be8('10', database);
    
    await be8.setup();
    return assert.equal(be8.hasGeneratedKeys(), true, 'Be8 object returns keys.');
});

QUnit.test('Get cached keys from db', async function (assert) {
    const be8Sender = new Be8('13', database);
    const be8Receiver = new Be8('14', database);
    await be8Receiver.setup();console.log('after setup');
    const publicKeys = await be8Sender.getCachedKeys();
    await be8Receiver.addPublicKeys(publicKeys);

    publicKeys.forEach(function ({ publicKey: { accID, crv, x, y } }) {
        assert.equal(crv, 'P-384', 'Curve is P-384');
        assert.equal(typeof x, 'string', 'x is a string');
        assert.equal(typeof y, 'string', 'y is a string');
        return assert.equal(!isNaN(accID), true, 'is a numeric string id');
    });
});

export default {};
