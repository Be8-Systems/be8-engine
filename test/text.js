// https://api.qunitjs.com/

import Be8 from './bundle.js';

const be8Sender = new Be8(1);
const be8Receiver = new Be8(2);
const be8spy = new Be8(3);

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
    const text = 'Hallo Welt';
    const [, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    const derivedKey = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const senderEncrypted = await be8Sender.encryptText(derivedKey, text);
    const receiverEncrypted = await be8Receiver.encryptText(derivedKey, text);
    const decryptedTextForSender = await be8Receiver.decryptText(derivedKey, senderEncrypted.cipherText, senderEncrypted.iv);
    const decryptedTextForReceiver = await be8Sender.decryptText(derivedKey, receiverEncrypted.cipherText, receiverEncrypted.iv);

    assert.equal(text, decryptedTextForReceiver, `"${text}"" is decrypted as "${decryptedTextForReceiver}"`);
    return assert.equal(text, decryptedTextForSender, `"${text}"" is decrypted as "${decryptedTextForSender}"`);
});

QUnit.test('IV changes at same message', async function (assert) {
    const text = 'Hallo Welt';
    const [, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    const derivedKey = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const textFirstDecrypt = await be8Sender.encryptText(derivedKey, text);
    const textSecondDecrypt = await be8Sender.encryptText(derivedKey, text);

    assert.notEqual(textFirstDecrypt.iv, textSecondDecrypt.iv, `Initialization vector is not equal after second time encrypting`);
    return assert.notEqual(textFirstDecrypt.cipherText, textSecondDecrypt.cipherText, `ciphertext is not equal after second time encrypting`);
});

QUnit.test('Communication between two and a third one is trying to decrypt', async function (assert) {
    const text = 'geheimer text';
    const [publicKeySENDER, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER, ] = await be8Receiver.generatePrivAndPubKey();
    const [, privateKeySpy] = await be8spy.generatePrivAndPubKey();
    const derivedKeySENDER = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const derivedKeySpy = await be8spy.getDerivedKey(publicKeySENDER, privateKeySpy);
    const textFirstDecrypt = await be8Sender.encryptText(derivedKeySENDER, text);
    const prom = be8spy.decryptText(derivedKeySpy, textFirstDecrypt.cipherText, textFirstDecrypt.iv);

    return assert.rejects(prom);
});

/*QUnit.test('', async function (assert) {

});*/
