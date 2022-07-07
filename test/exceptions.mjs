import database from './database.mjs';
import Be8 from './bundle.mjs';

const be8Sender = new Be8('1', database);
const be8Receiver = new Be8('2', database);

QUnit.module('Exceptions', {
    beforeEach: function () {
        return new Promise(function (resolve) {
            setTimeout(function () {
                return resolve(true);
            }, 100);
        });
    }
});

QUnit.test('Throw at constructor due to no id', async function (assert) {
    function fn () {
        return new Be8();
    }

    assert.throws(fn, /no acc id or wrong type passed to the constructor got undefined/, 'Throw at constructor due to no id');
});

QUnit.test('Throw at encryptTextSimple due to no sender key', async function (assert) {
    const receiver = '25';
    const be8Receiver = new Be8(receiver, database);

    await be8Receiver.setup();

    const text = 'Hallo Welt';
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    
    be8Receiver.addPublicKey(receiver, publicKeyRECEIVER);

    const prom = be8Receiver.encryptTextSimple('1', receiver, text);
    
    await be8Receiver.panic();
    return assert.rejects(prom, /Missing private key for 1 at encryptTextSimple/, 'Throw at encryptTextSimple due to no sender key');
});

QUnit.test('Throw at encryptTextSimple due to no receiver key', async function (assert) {
    const sender = '26';
    const be8Sender = new Be8(sender, database);
    const text = 'Hallo Welt';
    const [publicKeySENDER] = await be8Sender.generatePrivAndPubKey();
    
    be8Sender.addPublicKey(sender, publicKeySENDER);

    const prom = be8Sender.encryptTextSimple(sender, '2', text);
    
    await be8Sender.panic();
    return assert.rejects(prom, /Missing public key for 2 at encryptTextSimple/, 'Throw at encryptTextSimple due to no sender key');
});

QUnit.test('Throw at encryptImageSimple due to no sender key', async function (assert) {
    const receiver = '27';
    const be8Receiver = new Be8(receiver, database);

    await be8Receiver.setup();

    const text = 'Hallo Welt';
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    
    be8Receiver.addPublicKey(receiver, publicKeyRECEIVER);

    const prom = be8Receiver.encryptImageSimple('1', receiver, text);
    
    await be8Receiver.panic();
    return assert.rejects(prom, /Missing private key for 27 at encryptImageSimple/, 'Throw at encryptImageSimple due to no sender key');
});

QUnit.test('Throw at encryptImageSimple due to no receiver key', async function (assert) {
    const sender = '28';
    const be8Sender = new Be8(sender, database);

    await be8Sender.setup();

    const text = 'Hallo Welt';
    const [publicKeySENDER] = await be8Sender.generatePrivAndPubKey();
    
    be8Sender.addPublicKey(sender, publicKeySENDER);

    const prom = be8Sender.encryptImageSimple(sender, '2', text);
    
    await be8Sender.panic();
    return assert.rejects(prom, /Missing public key for 28 at encryptImageSimple/, 'Throw at encryptImageSimple due to no sender key');
});

QUnit.test('Throw at getDerivedKey due to missing public key' , async function (assert) {
    const be8Sender = new Be8('29', database);

    assert.rejects(be8Sender.getDerivedKey(), /no public key passed to getDerivedKey/, 'Throw at getDerivedKey due to missing public key');
    return await be8Sender.panic();
});

QUnit.test('Throw at getDerivedKey due to missing private key' , async function (assert) {
    const be8Sender = new Be8('30', database);
    const [publicKey] = await be8Sender.generatePrivAndPubKey();

    assert.rejects(be8Sender.getDerivedKey(publicKey), /no private key passed to getDerivedKey/, 'Throw at getDerivedKey due to missing private key');
    return await be8Sender.panic();
});

QUnit.test('Throw at encryptText due to missing derivedKey' , async function (assert) {
    const be8Sender = new Be8('31', database);

    assert.rejects(be8Sender.encryptText(), /no derived key passed to encryptText/, 'Throw at encryptText due to missing derivedKey');
    return await be8Sender.panic();
});

QUnit.test('Throw at decryptText due to missing derivedKey' , async function (assert) {
    const be8Sender = new Be8('32', database);

    assert.rejects(be8Sender.decryptText(), /no derived key passed to decryptText/, 'Throw at decryptText due to missing derivedKey');
    return await be8Sender.panic();
});

QUnit.test('Throw at decryptText due to missing iv' , async function (assert) {
    const sender = '33';
    const receiver = '34';
    const be8Sender = new Be8(sender, database);
    const be8Receiver = new Be8(receiver, database);

    await be8Sender.setup();
    await be8Receiver.setup();

    const senderPublicKeys = await be8Sender.getCachedKeys();
    const receiverPublicKeys = await be8Receiver.getCachedKeys();

    await be8Sender.addPublicKeys(receiverPublicKeys);
    await be8Receiver.addPublicKeys(senderPublicKeys);

    const text = 'Hallo Welt';
    const [publicKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();

    be8Sender.addPublicKey(receiver, publicKeyRECEIVER);
    be8Receiver.addPublicKey(sender, publicKeySENDER);

    const { cipherText } = await be8Sender.encryptTextSimple(sender, receiver, text);
    const prom = be8Sender.decryptTextSimple(receiver, sender, cipherText);

    await be8Sender.panic();
    await be8Receiver.panic();
    return assert.rejects(prom, /no iv \(Initialization vector\) passed to decryptText/, 'Throw at decryptText due to missing iv');
});