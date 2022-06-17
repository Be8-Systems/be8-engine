import Be8 from './bundle.mjs';

const base64Img = 'data:image/png;base64,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';
const be8Sender = new Be8('1');
const be8Receiver = new Be8('2');

QUnit.module('Images');

QUnit.test('decryptImage check if base64 is altered', async function (assert) {
    const [, privateKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    const derivedKey = await be8Sender.getDerivedKey(publicKeyRECEIVER, privateKeySENDER);
    const { iv, cipherImage } = await be8Sender.encryptImage(derivedKey, base64Img);
    
    assert.notEqual(cipherImage, base64Img, 'base64 is altered');
    assert.true(cipherImage.length > base64Img.length, 'cipherImage is longer than base64Img');

    const decryptedImage = await be8Sender.decryptImage(derivedKey, cipherImage, iv);
    
    assert.true(decryptedImage.length === base64Img.length, 'decryptedImage is as long as base64Img');
    return assert.equal(decryptedImage, base64Img, 'original base64 is returned');
});

QUnit.test('decryptImageSimple check if base64 is altered', async function (assert) {
    const [publicKeySENDER] = await be8Sender.generatePrivAndPubKey();
    const [publicKeyRECEIVER] = await be8Receiver.generatePrivAndPubKey();
    
    be8Sender.addPublicKey('1', publicKeySENDER);
    be8Sender.addPublicKey('2', publicKeyRECEIVER);
    be8Receiver.addPublicKey('1', publicKeySENDER);
    be8Receiver.addPublicKey('2', publicKeyRECEIVER);

    const { iv, cipherImage } = await be8Sender.encryptImageSimple('1', '2', base64Img);
    
    assert.notEqual(cipherImage, base64Img, 'base64 is altered');
    assert.true(cipherImage.length > base64Img.length, 'cipherImage is longer than base64Img');

    const decryptedImage = await be8Receiver.decryptImageSimple('1', '2', cipherImage, iv);
    
    assert.true(decryptedImage.length === base64Img.length, 'decryptedImage is as long as base64Img');
    return assert.equal(decryptedImage, base64Img, 'original base64 is returned');
});