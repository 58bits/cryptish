'use strict';

var Crypto = require("crypto");

var cryptish = function cryptish() {

  var internals = {};
  var exposed = {};

  // Defaults should be reset during init.
  var SALT_BITS = 32;
  var ITERATIONS = 2000;
  var KEY_LENGTH_BITS = 96;

  // Internal members

  internals.binaryToBase64 = function( binary ) {
    return new Buffer( binary, "binary" ).toString("base64");
  };

  internals.base64toBinary = function ( base64 ){
    return new Buffer( base64, "base64" ).toString("binary");
  };

  internals.fixedTimeComparison = function (a, b) {

    if (typeof a !== 'string' ||
        typeof b !== 'string') {

      return false;
    }

    var mismatch = (a.length === b.length ? 0 : 1);
    if (mismatch) {
      b = a;
    }

    for (var i = 0, il = a.length; i < il; ++i) {
      var ac = a.charCodeAt(i);
      var bc = b.charCodeAt(i);
      mismatch |= (ac ^ bc);
    }

    return (mismatch === 0);
  };

  // Public members

  exposed.init = function init(options) {
    SALT_BITS = options.saltBits;
    ITERATIONS = options.iterations;
    KEY_LENGTH_BITS = options.keyLength;
  };


  exposed.randomString = function randomString(size) {
    var buffer = exposed.randomBits((size + 1) * 6);
    if (buffer instanceof Error) {
      return buffer;
    }

    var string = internals.binaryToBase64(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    return string.slice(0, size);
  };

  exposed.randomBits = function randomBits(bits) {
    var bytes = Math.ceil(bits / 8);
    return Crypto.randomBytes(bytes);
  };

  exposed.generateSalt = function generateSalt(bits) {
    var buffer = exposed.randomBits(bits);
    return internals.binaryToBase64(buffer);
  };

  exposed.hashPassword = function hashPassword( value, salt ) {
    // if salt was not supplied, generate it now.
    if (salt == null ) {
      salt = exposed.generateSalt(SALT_BITS);
    }

    var derivedKey = internals.binaryToBase64(Crypto.pbkdf2Sync( value, salt, ITERATIONS, KEY_LENGTH_BITS, 'sha256'));
    return 'pbkdf2::' + salt + '::' + ITERATIONS + '::' + derivedKey;
  };

  exposed.verifyPassword = function verifyPassword( value, stored) {
    // if salt was not supplied, generate it now.
    var parts = stored.split('::');
    var salt = parts[1];
    var iterations = parseInt(parts[2]);
    var key = parts[3];
    var derivedKey = internals.binaryToBase64(Crypto.pbkdf2Sync( value, salt, iterations, KEY_LENGTH_BITS, 'sha256'));
    return internals.fixedTimeComparison(derivedKey, key);
  };

  exposed.binaryToBase64 = function binaryToBase64 (buffer) {
    return internals.binaryToBase64(buffer);
  };

  exposed.base64toBinary = function base64toBinary(string) {
    return internals.base64toBinary(string);
  };

  exposed.sha256 = function sha256(string) {
    if (!string) return string;
    return Crypto
        .createHash('sha256')
        .update(string)
        .digest('hex');
  };

  return exposed;

};

module.exports = cryptish();