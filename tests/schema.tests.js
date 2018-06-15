var jwt = require('../index');
var expect = require('chai').expect;
var fs = require('fs');

describe('schema', function() {

  describe('sign options', function() {

    var cert_rsa_priv = fs.readFileSync(__dirname + '/rsa-private.pem');
    var cert_ecdsa_priv = fs.readFileSync(__dirname + '/ecdsa-private.pem');

    function sign(options) {
      var isEcdsa = options.algorithm && options.algorithm.indexOf('ES') === 0;
      jwt.sign({foo: 123}, isEcdsa ? cert_ecdsa_priv : cert_rsa_priv, options);
    }

    it('should validate expiresIn', function () {
      sign({ expiresIn: '10s' });
      sign({ expiresIn: 10 });
    });

    it('should validate notBefore', function () {
      sign({ notBefore: '10s' });
      sign({ notBefore: 10 });
    });

    it('should validate audience', function () {
      sign({ audience: 'urn:foo' });
      sign({ audience: ['urn:foo'] });
    });

    it('should validate algorithm', function () {
      sign({algorithm: 'RS256'});
      sign({algorithm: 'RS384'});
      sign({algorithm: 'RS512'});
      sign({algorithm: 'ES256'});
      sign({algorithm: 'ES384'});
      sign({algorithm: 'ES512'});
      sign({algorithm: 'HS256'});
      sign({algorithm: 'HS384'});
      sign({algorithm: 'HS512'});
      sign({algorithm: 'none'});
    });

    it('should validate header', function () {
      sign({header: {}});
    });

    it('should validate encoding', function () {
      sign({encoding: 'utf8'});
    });

    it('should validate issuer', function () {
      sign({issuer: 'foo'});
    });

    it('should validate subject', function () {
      sign({subject: 'foo'});
    });

    it('should validate noTimestamp', function () {
      sign({noTimestamp: true});
    });

    it('should validate keyid', function () {
      sign({keyid: 'foo'});
    });

  });

});