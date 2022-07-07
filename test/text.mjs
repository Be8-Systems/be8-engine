import database from './database.mjs';
import Be8 from './bundle.mjs';

QUnit.module('Text', {
    beforeEach: function () {
        return new Promise(function (resolve) {
            setTimeout(function () {
                return resolve(true);
            }, 100);
        });
    }
});

QUnit.test('Encrypt and Decrypt text one way', async function (assert) {
    const be8Sender = new Be8('4', database);
    const be8Receiver = new Be8('5', database);

    await be8Sender.setup();
    await be8Receiver.setup();

    const senderPublicKeys = await be8Sender.getCachedKeys();
    const receiverPublicKeys = await be8Receiver.getCachedKeys();

    await be8Sender.addPublicKeys(receiverPublicKeys);
    await be8Receiver.addPublicKeys(senderPublicKeys);

    const text = 'Hallo Welt';
    const [, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    const derivedKey = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const { cipherText, iv } = await be8Sender.encryptText(derivedKey, text);
    const decryptedText = await be8Receiver.decryptText(derivedKey, cipherText, iv);

    await be8Sender.panic();
    await be8Receiver.panic();
    return assert.equal(text, decryptedText, `"${text}"" is decrypted as "${decryptedText}"`);
});

QUnit.test('Encrypt and Decrypt text duplex', async function (assert) {
    const be8Sender = new Be8('6', database);
    const be8Receiver = new Be8('7', database);

    await be8Sender.setup();
    await be8Receiver.setup();

    const senderPublicKeys = await be8Sender.getCachedKeys();
    const receiverPublicKeys = await be8Receiver.getCachedKeys();

    await be8Sender.addPublicKeys(receiverPublicKeys);
    await be8Receiver.addPublicKeys(senderPublicKeys);

    const text = 'Hallo Welt';
    const [, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    const derivedKey = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const senderEncrypted = await be8Sender.encryptText(derivedKey, text);
    const receiverEncrypted = await be8Receiver.encryptText(derivedKey, text);
    const decryptedTextForSender = await be8Receiver.decryptText(derivedKey, senderEncrypted.cipherText, senderEncrypted.iv);
    const decryptedTextForReceiver = await be8Sender.decryptText(derivedKey, receiverEncrypted.cipherText, receiverEncrypted.iv);

    await be8Sender.panic();
    await be8Receiver.panic();
    assert.equal(text, decryptedTextForReceiver, `"${text}"" is decrypted as "${decryptedTextForReceiver}"`);
    return assert.equal(text, decryptedTextForSender, `"${text}"" is decrypted as "${decryptedTextForSender}"`);
});

QUnit.test('IV changes at same message', async function (assert) {
    const be8Sender = new Be8('8', database);
    const be8Receiver = new Be8('9', database);

    await be8Receiver.setup();
    await be8Sender.setup();

    const senderPublicKeys = await be8Sender.getCachedKeys();
    const receiverPublicKeys = await be8Receiver.getCachedKeys();

    await be8Sender.addPublicKeys(receiverPublicKeys);
    await be8Receiver.addPublicKeys(senderPublicKeys);

    const text = 'Hallo Welt';
    const [, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    const derivedKey = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const textFirstDecrypt = await be8Sender.encryptText(derivedKey, text);
    const textSecondDecrypt = await be8Sender.encryptText(derivedKey, text);

    await be8Sender.panic();
    await be8Receiver.panic();
    assert.notEqual(textFirstDecrypt.iv, textSecondDecrypt.iv, `Initialization vector is not equal after second time encrypting`);
    return assert.notEqual(textFirstDecrypt.cipherText, textSecondDecrypt.cipherText, `ciphertext is not equal after second time encrypting`);
});

QUnit.test('Communication between two and a third one is trying to decrypt', async function (assert) {
    const be8Sender = new Be8('10', database);
    const be8Receiver = new Be8('11', database);
    const be8spy = new Be8('12', database);

    await be8Receiver.setup();
    await be8Sender.setup();

    const senderPublicKeys = await be8Sender.getCachedKeys();
    const receiverPublicKeys = await be8Receiver.getCachedKeys();

    await be8Sender.addPublicKeys(receiverPublicKeys);
    await be8Receiver.addPublicKeys(senderPublicKeys);
    
    const text = 'geheimer text';
    const [publicKeySENDER, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER, ] = await be8Receiver.generatePrivAndPubKey();
    const [, privateKeySpy] = await be8spy.generatePrivAndPubKey();
    const derivedKeySENDER = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const derivedKeySpy = await be8spy.getDerivedKey(publicKeySENDER, privateKeySpy);
    const textFirstDecrypt = await be8Sender.encryptText(derivedKeySENDER, text);
    const prom = be8spy.decryptText(derivedKeySpy, textFirstDecrypt.cipherText, textFirstDecrypt.iv);

    await be8Sender.panic();
    await be8Receiver.panic();
    await be8spy.panic();
    return assert.rejects(prom, 'The third one is not able to decrypt');
});

QUnit.test('Simplified encrypt and decrypt', async function (assert) {
    const senderID = '13';
    const receiverID = '14';
    const be8Sender = new Be8(senderID, database);
    const be8Receiver = new Be8(receiverID, database);

    await be8Sender.setup();
    await be8Receiver.setup();

    const senderPublicKeys = await be8Sender.getCachedKeys();
    const receiverPublicKeys = await be8Receiver.getCachedKeys();

    await be8Sender.addPublicKeys(receiverPublicKeys);
    await be8Receiver.addPublicKeys(senderPublicKeys);

    const text = 'Hallo Welt';
    const { iv, cipherText } = await be8Sender.encryptTextSimple(senderID, receiverID, text);
    const decryptText = await be8Sender.decryptTextSimple(receiverID, senderID, cipherText, iv);

    await be8Sender.panic();
    await be8Receiver.panic();
    return assert.equal(text, decryptText, `"${text}"" is decrypted as "${decryptText}"`);
});
