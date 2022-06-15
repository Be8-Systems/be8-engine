import Be8 from './bundle.js';

QUnit.module('Basics');

QUnit.test('Check if keys are generated', async function (assert) {
    const be8 = new Be8(1);
    
    await be8.generatePrivAndPubKey();
    return assert.equal(be8.hasKeys(), true, 'Be8 object returns keys.');
});
