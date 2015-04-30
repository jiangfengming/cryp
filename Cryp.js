var crypto = require('crypto');

function Cryp(ciphers) {
  this.ciphers = [].concat(ciphers);
}

Cryp.prototype = {
  encrypt: function(data, encoding) {
    if (data.constructor != Buffer)
      data = new Buffer(String(data));

    var cipher = this.ciphers[0];
    var iv = crypto.randomBytes(cipher.ivSize / 8);
    var cip = crypto.createCipheriv(cipher.algorithm, cipher.key, iv);
    data = Buffer.concat([iv, cip.update(data), cip.final()]);
    var checksum = crypto.createHmac('sha256', cipher.key).update(data).digest();
    data = Buffer.concat([checksum, data]);
    return encoding ? data.toString(encoding) : data;
  },

  decrypt: function(data, inputEncoding, outputEncoding) {
    if (data.constructor != Buffer)
      data = new Buffer(data, inputEncoding);
    else
      outputEncoding = inputEncoding;

    var checksum = data.slice(0, 32);
    data = data.slice(32);

    for (var i = 0; i < this.ciphers.length; i++) {
      var cipher = this.ciphers[i];
      if (!checksum.equals(crypto.createHmac('sha256', cipher.key).update(data).digest()))
        continue;
      var ivSize = cipher.ivSize / 8;
      var iv = data.slice(0, ivSize);
      data = data.slice(ivSize);
      var decip = crypto.createDecipheriv(cipher.algorithm, cipher.key, iv);
      data = Buffer.concat([decip.update(data), decip.final()]);
      return outputEncoding ? data.toString(outputEncoding) : data;
    }

    return null;
  },

  sign: function(data, encoding) {
    if (data.constructor != Buffer)
      data = new Buffer(String(data));

    var cipher = this.ciphers[0];
    var sign = crypto.createHmac('sha256', cipher.key).update(data).digest();
    return encoding ? sign.toString(encoding) : sign;
  },

  verify: function(data, sign, signEncoding) {
    if (data.constructor != Buffer)
      data = new Buffer(String(data));

    if (sign.constructor != Buffer)
      sign = new Buffer(sign, signEncoding);

    for (var i = 0; i < this.ciphers.length; i++) {
      var cipher = this.ciphers[i];
      if (sign.equals(crypto.createHmac('sha256', cipher.key).update(data).digest()))
        return true;
    }

    return false;
  }
};

module.exports = Cryp;
