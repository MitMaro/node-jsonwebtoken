var jwt = require('../index');

describe('keyid', function () {

  var claims = {"name": "doron", "age": 46};
  const token = jwt.sign(claims, 'secret', {"keyid": "1234"}, function(err, good) {
    console.log(jwt.decode(good, {"complete": true}).header.kid);
    jwt.verify(good, 'secret', function(err, result) {
      console.log(result);
    })
  });
});
