# Cryp.js

## Usage
```js
var Cryp = require('cryp');
var crypto = require('crypto');

// create a cryp object
var cryp = new Cryp([crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)]);

// encrypt
// cryp.encrypt(data, outputEncoding)
// data: utf-8 string or buffer
// if outputEncoding is undefined, return buffer. Otherwise return string encoded using outputEncoding
var data = cryp.encrypt('hello', 'base64');

// decrypt
// cryp.decrypt(data, [inputEncoding], outputEncoding)
// inputEncoding: the encoding of data. If data is a Buffer then dataEncoding is ignored.
// if outputEncoding is undefined, return buffer. Otherwise return string encoded using outputEncoding
cryp.decrypt(data, 'base64', 'utf8') == 'hello';

var data = cryp.encrypt('hello');
cryp.decrypt(data, 'utf8') == 'hello';
cryp.decrypt(data).toString() == 'hello';


// tamper the data
var data = cryp.encrypt('hello', 'base64');
data = 'a' + data;
// return null
cryp.decrypt(data, 'base64', 'utf8') == null;


// using rotate keys
var data = cryp.encrypt('hello', 'base64');
var cryp2 = new Cryp([
  crypto.pbkdf2Sync('NEWpASsWoRD', 'SaLt', 4096, 32),
  crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
]);
cryp2.decrypt(data, 'base64', 'utf8') == 'hello';

// sign data
// cryp.sign(data)
// data: buffer or utf-8 string
// return: signed string
var data = cryp.sign('hello');
cryp.unsign(data) == 'hello';

// tamper the signed data
var data = cryp.sign('hello');
data = 'a' + data;
// return null
cryp.unsign(data) == null;

// using rotate keys
var data = cryp.sign('hello');
var cryp2 = new Cryp([
  crypto.pbkdf2Sync('NEWpASsWoRD', 'SaLt', 4096, 32),
  crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
]);
cryp2.unsign(data) == 'hello';
```

## License
MIT
