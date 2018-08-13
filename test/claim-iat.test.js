'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');
const testUtils = require('./test-utils');

const base64UrlEncode = testUtils.base64UrlEncode;
const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

function signWithIssueAtSync(issueAt, options) {
  const payload = {};
  if (issueAt !== undefined) {
    payload.iat = issueAt;
  }
  const opts = Object.assign({algorithm: 'none'}, options);
  return jwt.sign(payload, undefined, opts);
}

function signWithIssueAtAsync(issueAt, options, cb) {
  const payload = {};
  if (issueAt !== undefined) {
    payload.iat = issueAt;
  }
  const opts = Object.assign({algorithm: 'none'}, options);
  return jwt.sign(payload, undefined, opts, cb);
}

function verifyWithIssueAtSync(token, maxAge, options) {
  const opts = Object.assign({maxAge}, options);
  return jwt.verify(token, undefined, opts)
}

function verifyWithIssueAtAsync(token, maxAge, options, cb) {
  const opts = Object.assign({maxAge}, options);
  return jwt.verify(token, undefined, opts, cb)
}

describe.only('xxxissue at', function() {
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
      it(`should error with iat of ${util.inspect(iat)} on synchronous call`, function () {
        expect(() => signWithIssueAtSync(iat, {})).to.throw('"iat" should be a number of seconds');
      });

      it(`should call callback with error with iat of ${util.inspect(iat)} on asynchronous call`, function (done) {
        signWithIssueAtAsync(iat, {}, (err) => {
          expect(err.message).to.equal('"iat" should be a number of seconds');
          done();
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {iat: undefined}
    it('should error with iat of undefined on synchronous call', function () {
      expect(() => jwt.sign({iat: undefined}, undefined, {algorithm: 'none'})).to.throw(
        '"iat" should be a number of seconds'
      );
    });

    it('should call callback with error with iat of undefined on asynchronous call', function (done) {
      jwt.sign({iat: undefined}, undefined, {algorithm: 'none'}, (err) => {
        expect(err.message).to.equal('"iat" should be a number of seconds');
        done();
      });
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
      it(`should error with iat of ${util.inspect(iat)} on synchronous call`, function () {
        const encodedPayload = base64UrlEncode(JSON.stringify({iat}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        expect(() => verifyWithIssueAtSync(token, '1 min', {})).to.throw(
          jwt.JsonWebTokenError, 'iat required when maxAge is specified'
        );
      });

      it(`should call callback with error with iat of ${util.inspect(iat)} on asynchronous call`, function () {
        const encodedPayload = base64UrlEncode(JSON.stringify({iat}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        verifyWithIssueAtAsync(token, '1 min', {}, (err) => {
          expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
          expect(err.message).to.equal('iat required when maxAge is specified')
        });
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

    it('should default to current time for "iat"', function (done) {
      const token = signWithIssueAtSync(undefined, {});
      const decoded = jwt.decode(token);
      expect(decoded.iat).to.equal(60);
      jwt.decode(token, undefined, (err, decoded) => {
        expect(err).to.be.undefined;
      })
    });

    // TODO an iat of -Infinity should fail validation
    it('should set null "iat" when given -Infinity', function () {
      const token = signWithIssueAtSync(-Infinity, {});
      const decoded = jwt.decode(token);
      expect(decoded.iat).to.be.null;
    });

    // TODO an iat of Infinity should fail validation
    it('should set null "iat" when given value Infinity', function () {
      const token = signWithIssueAtSync(Infinity, {});
      const decoded = jwt.decode(token);
      expect(decoded.iat).to.be.null;
    });

    // TODO an iat of NaN should fail validation
    it('should set to current time for "iat" when given value NaN', function () {
      const token = signWithIssueAtSync(NaN, {});
      const decoded = jwt.decode(token);
      expect(decoded.iat).to.equal(60);
    });

    it('should remove default "iat" with "noTimestamp" option', function () {
      const token = signWithIssueAtSync(undefined, {noTimestamp: true});
      const decoded = jwt.decode(token);
      expect(decoded).to.not.have.property('iat');
    });

    it('should remove provided "iat" with "noTimestamp" option', function () {
      const token = signWithIssueAtSync(10, {noTimestamp: true});
      const decoded = jwt.decode(token);
      expect(decoded).to.not.have.property('iat');
    });

    it('should verify using "iat" before the "maxAge"', function () {
      const token = signWithIssueAtSync(undefined, {});
      fakeClock.tick(10000);
      expect(verifyWithIssueAtSync(token, 11, {})).to.not.throw;
    });

    it('should verify using "iat" before the "maxAge" with a provided "clockTimestamp', function () {
      const token = signWithIssueAtSync(undefined, {});
      fakeClock.tick(60000);
      expect(verifyWithIssueAtSync(token, 11, {clockTimestamp: 70})).to.not.throw;
    });

    it('should verify using "iat" after the "maxAge" but within "clockTolerance"', function () {
      const token = signWithIssueAtSync(undefined, {});
      fakeClock.tick(10000);
      expect(verifyWithIssueAtSync(token, 9, {clockTolerance: 2})).to.not.throw;
    });

    it('should throw using "iat" equal to the "maxAge"', function () {
      const token = signWithIssueAtSync(undefined, {});
      fakeClock.tick(10000);
      expect(() => verifyWithIssueAtSync(token, 10, {}))
        .to.throw(jwt.TokenExpiredError, 'maxAge exceeded')
        .to.have.property('expiredAt').that.deep.equals(new Date(70000));
    });

    it('should throw using "iat" after the "maxAge"', function () {
      const token = signWithIssueAtSync(undefined, {});
      fakeClock.tick(10000);
      expect(() => verifyWithIssueAtSync(token, 9, {}))
        .to.throw(jwt.TokenExpiredError, 'maxAge exceeded')
        .to.have.property('expiredAt').that.deep.equals(new Date(69000));
    });

    it('should throw using "iat" after the "maxAge" with a provided "clockTimestamp', function () {
      const token = signWithIssueAtSync(undefined, {});
      fakeClock.tick(60000);
      expect(() => verifyWithIssueAtSync(token, 10, {clockTimestamp: 70}))
        .to.throw(jwt.TokenExpiredError, 'maxAge exceeded')
        .to.have.property('expiredAt').that.deep.equals(new Date(70000));
    });

    it('should throw using "iat" after the "maxAge" and "clockTolerance', function () {
      const token = signWithIssueAtSync(undefined, {});
      fakeClock.tick(10000);
      expect(() => verifyWithIssueAtSync(token, 8, {clockTolerance: 2}))
        .to.throw(jwt.TokenExpiredError, 'maxAge exceeded')
        .to.have.property('expiredAt').that.deep.equals(new Date(68000));
    });
  });
});
