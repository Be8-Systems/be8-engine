import Be8 from './bundle.js';

const be8Sender = new Be8(1);
const be8Receiver = new Be8(2);

QUnit.module('Text');

QUnit.test('Encrypt and Decrypt text one way', async function (assert) {
    const text = 'Hallo Welt';
    const [, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    const derivedKey = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const { cipherText, iv } = await be8Sender.encryptText(derivedKey, text);
    const decryptedText = await be8Receiver.decryptText(derivedKey, cipherText, iv);

    return assert.equal(text, decryptedText, `"${text}"" is decrypted as "${decryptedText}"`);
});

QUnit.test('Encrypt and Decrypt text duplex', async function (assert) {

});

QUnit.test('IV changes at same message', async function (assert) {

});

QUnit.test('Communication between two and a third one is trying to decrypt', async function (assert) {

});

