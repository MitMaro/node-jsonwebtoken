'use strict';

const jwt = require('../');

const expect = require('chai').expect;

describe('sign validation', function() {
  describe('for options', function() {
    [
      {
        description: 'with expiresIn as a string with an invalid unit',
        options: {expiresIn: '1 monkey'},
        expectedError: '"expiresIn" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'with expiresIn as a float',
        options: {expiresIn: 1.1},
        expectedError: '"expiresIn" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'with notBefore as a string with an invalid unit',
        options: {notBefore: '1 monkey'},
        expectedError: '"notBefore" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'with notBefore as a float',
        options: {notBefore: 1.1},
        expectedError: '"notBefore" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'with a non-string audience',
        options: {audience: 10},
        expectedError: '"audience" must be a string or array'
      },
      {
        description: 'with a algorithm not in allowed list',
        options: {algorithm: 'invalid'},
        expectedError: '"algorithm" must be a valid string enum value'
      },
      {
        description: 'with a non-object header ',
        options: {header: 'invalid'},
        expectedError: '"header" must be an object'
      },
      {
        description: 'with a non-string encoding',
        options: {encoding: 10},
        expectedError: '"encoding" must be a string'
      },
      {
        description: 'with a non-string issuer',
        options: {issuer: 10},
        expectedError: '"issuer" must be a string'
      },
      {
        description: 'with a non-string subject',
        options: {subject: 10},
        expectedError: '"subject" must be a string'
      },
      {
        description: 'with a non-boolean noTimestamp',
        options: {noTimestamp: 'invalid'},
        expectedError: '"noTimestamp" must be a boolean'
      },
      {
        description: 'with a non-string keyid',
        options: {keyid: 10},
        expectedError: '"keyid" must be a string'
      }
    ].forEach((testCase) => {
      it(`should error ${testCase.description}`, function() {
        expect(() => jwt.sign({}, 'secret', testCase.options)).to.throw(testCase.expectedError);
      });
    });
  })
});