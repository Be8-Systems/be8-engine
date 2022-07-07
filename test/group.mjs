import database from './database.mjs';
import Be8 from './bundle.mjs';

QUnit.module('Groups', {
    beforeEach: function () {
        return new Promise(function (resolve) {
            setTimeout(function () {
                return resolve(true);
            }, 100);
        });
    }
});

QUnit.test('Generate Group Message, readable for everyone, 3 participants', async function (assert) {
    let groupversion = 1;
    const be8groupOwner = new Be8('15', database);
    const be8Second = new Be8('16', database);
    const be8Third = new Be8('17', database);
    const ownerKeys = await be8groupOwner.generatePrivAndPubKey();
    const [, groupKeysV1] = await be8groupOwner.generateGroupKeys(groupversion);
    const text = 'hello world'; 
    const gOwnerDerivedKey = await be8groupOwner.getDerivedKey(ownerKeys[0], groupKeysV1);
    const { cipherText, iv } = await be8groupOwner.encryptText(gOwnerDerivedKey, text);
    const secondText = await be8Second.decryptText(gOwnerDerivedKey, cipherText, iv); 
    const thirdText = await be8Third.decryptText(gOwnerDerivedKey, cipherText, iv);  

    await be8groupOwner.panic();
    await be8Second.panic();
    await be8Third.panic();
    assert.equal(text, secondText, 'Second participant can read the message');
    return assert.equal(text, thirdText, 'Third participant can read the message');
});

QUnit.test('Generate Group Message, 2 participants regenerate after a third one joins', async function (assert) {
    let groupversion = 1;
    const be8groupOwner = new Be8('18', database);
    const be8Second = new Be8('19', database);
    const be8Third = new Be8('20', database);
    const ownerKeys = await be8groupOwner.generatePrivAndPubKey();
    const secondKeys = await be8Second.generatePrivAndPubKey();
    const [, groupKeysV1] = await be8groupOwner.generateGroupKeys(groupversion);
    const firstMessage = 'hello world'; 
    const gOwnerDerivedKey = await be8groupOwner.getDerivedKey(ownerKeys[0], groupKeysV1);
    const { cipherText, iv } = await be8groupOwner.encryptText(gOwnerDerivedKey, firstMessage);
    const cipherDecryptBySecond = await be8Second.decryptText(gOwnerDerivedKey, cipherText, iv); 

    assert.equal(firstMessage, cipherDecryptBySecond, 'Phase 1: Second participant can decrypt message');
    
    // Add new people to the group
    groupversion++; 

    const [, groupKeysV2] = await be8groupOwner.generateGroupKeys(groupversion);
    const gOwnerDerivedKeyV2 = await be8groupOwner.getDerivedKey(ownerKeys[0], groupKeysV2);
    const secondMessage = 'Willkommen zu der Gruppe';
    const secondCipherMessage = await be8Second.encryptText(gOwnerDerivedKeyV2, secondMessage);
    const secondMessageDecryptBySecond = await be8Second.decryptText(gOwnerDerivedKeyV2, secondCipherMessage.cipherText, secondCipherMessage.iv);
    const secondMessageDecryptByThird = await be8Third.decryptText(gOwnerDerivedKeyV2, secondCipherMessage.cipherText, secondCipherMessage.iv);

    assert.equal(secondMessageDecryptBySecond, secondMessage, 'Phase 2: Second participant can decrypt second message');
    assert.equal(secondMessageDecryptByThird, secondMessage, 'Phase 2: Third participant can decrypt second message');

    const firstMessageDecryptByNewerKey = be8Third.decryptText(gOwnerDerivedKeyV2, cipherText, iv);

    await be8groupOwner.panic();
    await be8Second.panic();
    await be8Third.panic();
    assert.rejects(firstMessageDecryptByNewerKey, 'Phase 3: prevent new member to read old message');
});