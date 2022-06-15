import Be8 from './bundle.mjs';

const be8 = new Be8('1');

QUnit.module('Exceptions');

QUnit.test('Throw at constructor due to no id', async function (assert) {
    function fn () {
        return new Be8();
    }

    assert.throws(fn, /no acc id passed to constructor/, 'Throw at constructor due to no id');
});

QUnit.test('Throw at encryptTextSimple due to no id', async function (assert) {

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