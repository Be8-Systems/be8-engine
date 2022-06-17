import Be8 from './bundle.mjs';

const be8Sender = new Be8('1');
const be8Receiver = new Be8('2');

QUnit.module('Exceptions');

QUnit.test('Throw at constructor due to no id', async function (assert) {
    function fn () {
        return new Be8();
    }

    assert.throws(fn, /no acc id passed to constructor/, 'Throw at constructor due to no id');
});

QUnit.test('Throw at encryptTextSimple due to no sender key', async function (assert) {
    const text = 'Hallo Welt';
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    
    be8Receiver.addPublicKey('2', publicKeyRECEIVER);

    const prom = be8Receiver.encryptTextSimple('1', '2', text);
    
    return assert.rejects(prom, /Missing private key for 1 at encryptTextSimple/, 'Throw at encryptTextSimple due to no sender key');
});

QUnit.test('Throw at encryptTextSimple due to no receiver key', async function (assert) {
    const text = 'Hallo Welt';
    const [publicKeySENDER] = await be8Sender.generatePrivAndPubKey();
    
    be8Sender.addPublicKey('1', publicKeySENDER);

    const prom = be8Sender.encryptTextSimple('1', '2', text);
    
    return assert.rejects(prom, /Missing public key for 2 at encryptTextSimple/, 'Throw at encryptTextSimple due to no sender key');
});

QUnit.test('Throw at getDerivedKey due to missing public key' , async function (assert) {

});

QUnit.test('Throw at getDerivedKey due to missing private key' , async function (assert) {

});

QUnit.test('Throw at encryptText due to missing derivedKey' , async function (assert) {

});

QUnit.test('Throw at decryptText due to missing derivedKey' , async function (assert) {

});

QUnit.test('Throw at decryptText due to missing iv' , async function (assert) {

});