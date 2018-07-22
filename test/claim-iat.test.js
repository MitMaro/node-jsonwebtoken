'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');
const testUtils = require('./test-utils');

const base64UrlEncode = testUtils.base64UrlEncode;
const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

function signWithIssueAt(issueAt, options = {}) {
  const payload = {};
  if (issueAt !== undefined) {
    payload.iat = issueAt;
  }
  const opts = Object.assign({algorithm: 'none'}, options);
  return jwt.sign(payload, undefined, opts);
}

function verifyWithIssueAt(token, maxAge, options = {}) {
  const opts = Object.assign({maxAge}, options);
  return jwt.verify(token, undefined, opts)
}

describe('issue at', function() {
  describe('`jwt.sign` "iat" claim validation', function () {
    [
      true,
      false,
      null,
      '',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((iat) => {
      it(`should error with value ${util.inspect(iat)}`, function () {
        expect(() => signWithIssueAt(iat)).to.throw('"iat" should be a number of seconds');
      });
    });

    // undefined needs special treatment because {} is not the same as {iat: undefined}
    it('should error with with value undefined', function () {
      expect(() =>jwt.sign({iat: undefined}, undefined, {algorithm: 'none'})).to.throw('"iat" should be a number of seconds');
    });
  });

  describe('"iat" in payload with "maxAge" option validation', function () {
    [
      true,
      false,
      null,
      undefined,
      -Infinity,
      Infinity,
      NaN,
      '',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((iat) => {
      it(`should error with with value ${util.inspect(iat)}`, function () {
        const encodedPayload = base64UrlEncode(JSON.stringify({iat}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        expect(() => verifyWithIssueAt(token, '1 min')).to.throw(jwt.JsonWebTokenError, 'iat required when maxAge is specified'
        );
      });
    })
  });

  describe('when signing and verifying a token with issue at', function () {
    let fakeClock;
    beforeEach(function() {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function() {
      fakeClock.uninstall();
    });

    it('should default to current time for "iat"', function () {
      const token = signWithIssueAt();
      const decoded = jwt.decode(token);
      expect(decoded.iat).to.equal(60);
    });

    // TODO an iat of -Infinity should fail validation
    it('should set null "iat" when given -Infinity', function () {
      const token = signWithIssueAt(-Infinity);
      const decoded = jwt.decode(token);
      expect(decoded.iat).to.be.null;
    });

    // TODO an iat of Infinity should fail validation
    it('should set null "iat" when given value Infinity', function () {
      const token = signWithIssueAt(Infinity);
      const decoded = jwt.decode(token);
      expect(decoded.iat).to.be.null;
    });

    // TODO an iat of NaN should fail validation
    it('should set to current time for "iat" when given value NaN', function () {
      const token = signWithIssueAt(NaN);
      const decoded = jwt.decode(token);
      expect(decoded.iat).to.equal(60);
    });

    it('should remove default "iat" with "noTimestamp" option', function () {
      const token = signWithIssueAt(undefined, {noTimestamp: true});
      const decoded = jwt.decode(token);
      expect(decoded).to.not.have.property('iat');
    });

    it('should remove provided "iat" with "noTimestamp" option', function () {
      const token = signWithIssueAt(10, {noTimestamp: true});
      const decoded = jwt.decode(token);
      expect(decoded).to.not.have.property('iat');
    });

    it('should verify using "iat" before the "maxAge"', function () {
      const token = signWithIssueAt();
      fakeClock.tick(10000);
      expect(verifyWithIssueAt(token, 11)).to.not.throw;
    });

    it('should verify using "iat" before the "maxAge" with a provided "clockTimestamp', function () {
      const token = signWithIssueAt();
      fakeClock.tick(60000);
      expect(verifyWithIssueAt(token, 11, {clockTimestamp: 70})).to.not.throw;
    });

    it('should verify using "iat" after the "maxAge" but within "clockTolerance"', function () {
      const token = signWithIssueAt();
      fakeClock.tick(10000);
      expect(verifyWithIssueAt(token, 9, {clockTolerance: 2})).to.not.throw;
    });

    it('should throw using "iat" equal to the "maxAge"', function () {
      const token = signWithIssueAt();
      fakeClock.tick(10000);
      expect(() => verifyWithIssueAt(token, 10))
        .to.throw(jwt.TokenExpiredError, 'maxAge exceeded')
        .to.have.property('expiredAt').that.deep.equals(new Date(70000));
    });

    it('should throw using "iat" after the "maxAge"', function () {
      const token = signWithIssueAt();
      fakeClock.tick(10000);
      expect(() => verifyWithIssueAt(token, 9))
        .to.throw(jwt.TokenExpiredError, 'maxAge exceeded')
        .to.have.property('expiredAt').that.deep.equals(new Date(69000));
    });

    it('should throw using "iat" after the "maxAge" with a provided "clockTimestamp', function () {
      const token = signWithIssueAt();
      fakeClock.tick(60000);
      expect(() => verifyWithIssueAt(token, 10, {clockTimestamp: 70}))
        .to.throw(jwt.TokenExpiredError, 'maxAge exceeded')
        .to.have.property('expiredAt').that.deep.equals(new Date(70000));
    });

    it('should throw using "iat" after the "maxAge" and "clockTolerance', function () {
      const token = signWithIssueAt();
      fakeClock.tick(10000);
      expect(() => verifyWithIssueAt(token, 8, {clockTolerance: 2}))
        .to.throw(jwt.TokenExpiredError, 'maxAge exceeded')
        .to.have.property('expiredAt').that.deep.equals(new Date(68000));
    });
  });
});
