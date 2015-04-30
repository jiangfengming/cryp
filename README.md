```js
var Cryp = require('./Cryp');
var crypto = require('crypto');

var cryp = new Cryp([{
  algorithm: 'aes-256-cfb',
  ivSize: 128,
  key: crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
}, {
  algorithm: 'aes-256-cfb',
  ivSize: 128,
  key: crypto.pbkdf2Sync('OlDpaSSwoRd', 'sAlt', 4096, 32)
}]);

var cryp2 = new Cryp([{
  algorithm: 'aes-256-cfb',
  ivSize: 128,
  key: crypto.pbkdf2Sync('newPasSword', 'sAlt', 4096, 32)
}, {
  algorithm: 'aes-256-cfb',
  ivSize: 128,
  key: crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
}]);

var data = 'hello';
var sign = cryp.sign(data, 'base64');
console.log(sign);
console.log(cryp.verify(data, sign, 'base64'));
console.log(cryp2.verify(data, sign, 'base64'));

var secret = cryp.encrypt(data, 'base64');
console.log(secret);
console.log(cryp2.decrypt(secret, 'base64', 'utf8'));
```
