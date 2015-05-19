var crypto = require('crypto');

function Cryp(keys) {
  this.keys = [].concat(keys);
}

Cryp.prototype = {
  encrypt: function(data, encoding) {
    if (data.constructor != Buffer)
      data = new Buffer(String(data));

    var key = this.keys[0];
    var iv = crypto.randomBytes(12);
    var cip = crypto.createCipheriv('aes-256-gcm', key, iv);
    data = Buffer.concat([cip.update(data), cip.final(), cip.getAuthTag(), iv]);
    return encoding ? data.toString(encoding) : data;
  },

  decrypt: function(data, inputEncoding, outputEncoding) {
    if (data.constructor != Buffer)
      data = new Buffer(data, inputEncoding);
    else if (!outputEncoding)
      outputEncoding = inputEncoding;

    var iv = data.slice(-12);
    var tag = data.slice(-28, -12);
    data = data.slice(0, -28);

    try {
      for (var i = 0; i < this.keys.length; i++) {
        var key = this.keys[i];
        var decip = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decip.setAuthTag(tag);
        try { // tag is incorrect, use old key to retry
          data = Buffer.concat([decip.update(data), decip.final()]);
        } catch (e) {
          continue;
        }
        return outputEncoding ? data.toString(outputEncoding) : data;
      }
    } catch (e) {
      return null;
    }

    return null;
  },

  sign: function(data) {
    if (data.constructor != Buffer)
      data = new Buffer(String(data));

    var sign = base64url.encode(this.getSign(data));
    return data.toString() + sign;
  },

  unsign: function(data) {
    var sign = base64url.decode(data.slice(-38));
    data = data.slice(0, -38);
    return this.verify(data, sign) ? data : null;
  },

  getSign: function(data, encoding) {
    if (data.constructor != Buffer)
      data = new Buffer(String(data));

    var key = this.keys[0];
    var sign = crypto.createHmac('sha224', key).update(data).digest();
    return encoding ? sign.toString(encoding) : sign;
  },

  verify: function(data, sign, signEncoding) {
    if (data.constructor != Buffer)
      data = new Buffer(String(data));

    if (sign.constructor != Buffer)
      sign = new Buffer(sign, signEncoding);

    for (var i = 0; i < this.keys.length; i++) {
      var key = this.keys[i];
      if (sign.equals(crypto.createHmac('sha224', key).update(data).digest()))
        return true;
    }

    return false;
  }
};

var base64url = {
  encode: function(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  },

  decode: function(str) {
    return new Buffer(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  }
};

module.exports = Cryp;
