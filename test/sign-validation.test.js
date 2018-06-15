'use strict';

const jwt = require('../');

const expect = require('chai').expect;

describe('sign validation', function() {
  describe('for options', function() {
    [
      {
        description: 'when not passed an object',
        options: 'not an object',
        expectedError: 'Expected "options" to be a plain object.'
      },
      {
        description: 'when passed an unknown option',
        options: {invalid: 'value'},
        expectedError: '"invalid" is not allowed in "options"'
      },
      {
        description: 'when passed the deprecated "expiresInSeconds" option',
        options: {expiresInSeconds: 'value'},
        expectedError: '"expiresInSeconds" is not allowed in "options"'
      },
      {
        description: 'with "expiresIn" as a string with an invalid unit',
        options: {expiresIn: '1 monkey'},
        expectedError: '"expiresIn" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'with "expiresIn" as a float',
        options: {expiresIn: 1.1},
        expectedError: '"expiresIn" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'when "expiresIn" is provided with "exp" in payload',
        options: {expiresIn: 100},
        payload: {exp: 200},
        expectedError: 'Bad "options.expiresIn" option the payload already has an "exp" property.'
      },
      {
        description: 'with "notBefore" as a string with an invalid unit',
        options: {notBefore: '1 monkey'},
        expectedError: '"notBefore" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'with "notBefore" as a float',
        options: {notBefore: 1.1},
        expectedError: '"notBefore" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'when "notBefore" is provided with "nbf" in payload',
        options: {notBefore: 100},
        payload: {nbf: 200},
        expectedError: 'Bad "options.notBefore" option the payload already has an "nbf" property.'
      },
      {
        description: 'with a non-string or non-array "audience"',
        options: {audience: 10},
        expectedError: '"audience" must be a string or array'
      },
      {
        description: 'when "audience" is provided with "aud" in payload',
        options: {audience: 'audience'},
        payload: {aud: 'aud'},
        expectedError: 'Bad "options.audience" option. The payload already has an "aud" property.'
      },
      {
        description: 'with a "algorithm" not in allowed list',
        options: {algorithm: 'invalid'},
        expectedError: '"algorithm" must be a valid string enum value'
      },
      {
        description: 'with a non-object "header"',
        options: {header: 'invalid'},
        expectedError: '"header" must be an object'
      },
      {
        description: 'with a non-string "encoding"',
        options: {encoding: 10},
        expectedError: '"encoding" must be a string'
      },
      {
        description: 'with a non-string "issuer"',
        options: {issuer: 10},
        expectedError: '"issuer" must be a string'
      },
      {
        description: 'when "issuer" is provided with "iss" in payload',
        options: {issuer: 'issuer'},
        payload: {iss: 'iss'},
        expectedError: 'Bad "options.issuer" option. The payload already has an "iss" property.'
      },
      {
        description: 'with a non-string "subject"',
        options: {subject: 10},
        expectedError: '"subject" must be a string'
      },
      {
        description: 'when "subject" is provided with "sub" in payload',
        options: {subject: 'subject'},
        payload: {sub: 'sub'},
        expectedError: 'Bad "options.subject" option. The payload already has an "sub" property.'
      },
      {
        description: 'with a non-string "jwtid"',
        options: {jwtid: 10},
        expectedError: '"jwtid" must be a string'
      },
      {
        description: 'when "jwtid" is provided with "jti" in payload',
        options: {jwtid: 'jwtid'},
        payload: {jti: 'jti'},
        expectedError: 'Bad "options.jwtid" option. The payload already has an "jti" property.'
      },
      {
        description: 'with a non-boolean "noTimestamp"',
        options: {noTimestamp: 'invalid'},
        expectedError: '"noTimestamp" must be a boolean'
      },
      {
        description: 'with a non-string "keyid"',
        options: {keyid: 10},
        expectedError: '"keyid" must be a string'
      },
      {
        description: 'with a non-string "keyid"',
        options: {keyid: 10},
        expectedError: '"keyid" must be a string'
      },
      {
        description: 'with a non-string "mutatePayload"',
        options: {mutatePayload: 'invalid'},
        expectedError: '"mutatePayload" must be a boolean'
      }
    ].forEach((testCase) => {
      it(`should error ${testCase.description}`, function() {
        expect(() => jwt.sign(testCase.payload || {}, 'secret', testCase.options)).to.throw(testCase.expectedError);
      });
    });
  });

  describe('for payload', function() {
    [
      {
        description: 'when provided an undefined payload',
        payload: undefined,
        expectedError: 'payload is required'
      },
      {
        description: 'with a non-number "iat" claim',
        payload: {iat: 'invalid'},
        expectedError: '"iat" should be a number of seconds'
      },
      {
        description: 'with a non-number "exp" claim',
        payload: {exp: 'invalid'},
        expectedError: '"exp" should be a number of seconds'
      },
      {
        description: 'with a non-string "nbf" claim',
        payload: {nbf: 'invalid'},
        expectedError: '"nbf" should be a number of seconds'
      },
    ].forEach((testCase) => {
      it(`should error ${testCase.description}`, function() {
        expect(() => jwt.sign(testCase.payload, 'secret', {})).to.throw(testCase.expectedError);
      });
    });
  });
});