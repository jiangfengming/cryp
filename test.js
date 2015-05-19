var Cryp = require('./Cryp');
var crypto = require('crypto');
var assert = require('assert');

describe('Cryp', function() {
  var cryp = new Cryp([crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)]);

  it('should encrypt a value', function() {
    var data = cryp.encrypt('hello', 'base64');
    assert.equal(cryp.decrypt(data, 'base64', 'utf8'), 'hello');
  });

  it('should encrypt a value #2', function() {
    var data = cryp.encrypt('hello');
    assert.equal(cryp.decrypt(data, 'utf8'), 'hello');
    assert.equal(cryp.decrypt(data).toString(), 'hello');
  });

  it('should return null', function() {
    var data = cryp.encrypt('hello', 'base64');
    data = 'a' + data;
    assert.equal(cryp.decrypt(data, 'base64', 'utf8'), null);
  });

  it('should decrypt with rotate keys', function() {
    var data = cryp.encrypt('hello', 'base64');
    var cryp2 = new Cryp([
      crypto.pbkdf2Sync('NEWpASsWoRD', 'SaLt', 4096, 32),
      crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
    ]);
    assert.equal(cryp2.decrypt(data, 'base64', 'utf8'), 'hello');
  });

  it('should sign a value', function() {
    var data = cryp.sign('hello');
    assert.equal(cryp.unsign(data), 'hello');
  });

  it('should return null', function() {
    var data = cryp.sign('hello');
    data = 'a' + data;
    assert.equal(cryp.unsign(data), null);
  });

  it('should unsign with rotate keys', function() {
    var data = cryp.sign('hello');
    var cryp2 = new Cryp([
      crypto.pbkdf2Sync('NEWpASsWoRD', 'SaLt', 4096, 32),
      crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
    ]);
    assert.equal(cryp2.unsign(data), 'hello');
  });
});
