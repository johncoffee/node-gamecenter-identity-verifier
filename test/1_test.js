/*
global toString
 */
'use strict';

var assert = require('assert');
var crypto = require('crypto');
var fs = require('fs');
var verifier = require('../lib/main');
var nock = require('nock');

function calculateSignature(payload) {
  var privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');
  var signer = crypto.createSign('sha256');
  signer.update(payload.playerId, 'utf8');
  signer.update(payload.bundleId, 'utf8');
  signer.update(verifier.convertTimestampToBigEndian(payload.timestamp));
  signer.update(payload.salt, 'base64');

  var signature = signer.sign(privateKey, 'base64');
  return signature;
}

describe('verifying gameCenter identity', function () {

  beforeEach(function () {

    nock('https://valid.apple.com')
      .get('/public/public.cer')
      .replyWithFile(200, __dirname + '/fixtures/public.der');
  });

  // TODO timeouts are out of scope for now
  // xit('should fail to verify apple game center identity if request is failed(timeout)',
  //   function (done) {
  //   var testToken = {
  //     publicKeyUrl: 'https://valid.apple.com/public/timeout.cer',
  //     timestamp: 1460981421303,
  //     salt: 'saltST==',
  //     playerId: 'G:1111111',
  //     bundleId: 'com.valid.app'
  //   };
  //   testToken.signature = calculateSignature(testToken);
  //
  //   verifier.verify(testToken, function (error, token) {
  //     assert(error instanceof verifier.SignatureValidationError);
  //     assert.equal(error.message, 'timeout');
  //     assert.equal(token, null);
  //     done();
  //   });
  // });

  it('should succeed to verify apple game center identity',
  async function () {
    var testToken = {
      publicKeyUrl: 'https://valid.apple.com/public/public.cer',
      timestamp: 1460981421303,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    const isValid = await verifier.verify(testToken, false);
    assert.strictEqual(isValid, true)
  });

  /*jshint multistr: true */
  it('should succeed to verify identity when most significant (left-most) bit of \
timestamp high and low bit block is 1',
    async function () {
    var testToken = {
      publicKeyUrl: 'https://valid.apple.com/public/public.cer',
      timestamp: 1462525134342,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    const isValid = await verifier.verify(testToken, false);
    assert.strictEqual(isValid, true)
  });

  it('should fail to get publicKey with http: protocol', async function () {
    var testToken = {
      publicKeyUrl: 'http://valid.apple.com/public/public.cer',
      timestamp: 1460981421303,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    try {
      await verifier.verify(testToken, false)
    }
    catch (error) {
      assert(error instanceof verifier.SignatureValidationError);
      assert.strictEqual(error.message, 'Invalid publicKeyUrl: should use https');
      return
    }

    assert.fail('should have thrown')
  });

  it('should fail to get publicKey if domain is not apple.com',
  async function () {
    var testToken = {
      publicKeyUrl: 'https://invalid.badapple.com/public/public.cer',
      timestamp: 1460981421303,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    try {
      await verifier.verify(testToken, false)
    }
    catch(error) {
      assert(error instanceof verifier.SignatureValidationError);
      assert.strictEqual(error.message, 'Invalid publicKeyUrl: host should be apple.com');
      return
    };

    assert.fail('should have thrown')
  });

  it('should fail to verify signature if signature is invalid',
  async function () {
    var testToken = {
      publicKeyUrl: 'https://valid.apple.com/public/public.cer',
      timestamp: 123,
      salt: Buffer.from([3,2,1]).toString('base64'),
      playerId: 'G:111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);
    testToken.salt = Buffer.from([1,2,3]).toString('base64')

    const isValid = await verifier.verify(testToken, false)
      .catch(error => assert.fail('should not throw '+error))

    assert.strictEqual(isValid, false)

  });
});
