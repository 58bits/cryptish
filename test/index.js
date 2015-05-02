'use strict';

// Load modules

var Lab = require('lab');
var Cryptish = require('../lib/');

// Declare internals

var internals = {};


// Test shortcuts

var lab = exports.lab = Lab.script();
var before = lab.before;
var after = lab.after;
var describe = lab.describe;
var it = lab.it;
var expect = Lab.expect;

describe('Cryptish', function () {
  describe('#randomString', function() {
    it("should create a randomString of the specified length ", function(done){
      var string = Cryptish.randomString(20);
      expect(string.length).to.equal(20);
      done();
    });
  });

  describe('#randomBits', function() {
    it("should create randombits of the specified length ", function(done){
      var buffer = Cryptish.randomBits(64);
      expect(buffer.length).to.equal(64 / 8);
      done();
    });
  });

  describe('#generateSalt', function() {
    it("should create a base64 encoded string of the specified length in bits ", function(done){
      var string = Cryptish.generateSalt(64);
      var buffer = Cryptish.base64toBinary(string);
      expect(buffer.length).to.equal(64/ 8);
      done();
    });
  });

  describe('#hashPassword', function() {
    it("should create derived password with the algorithm, salt, derived password and iterations in a string ", function(done){
      var string = Cryptish.hashPassword('welcome');
      var parts = string.split('::');
      expect(parts.length).to.equal(4);
      done();
    });
  });

  describe('#verifyPassword', function() {
    it("should verify a correct password ", function(done){
      var user = internals.user();
      var result = Cryptish.verifyPassword('welcome', user.password);
      expect(result).to.equal(true);
      done();
    });
  });

  describe('#verifyPassword', function() {
    it("should fail an incorrect password ", function(done){
      var user = internals.user();
      var result = Cryptish.verifyPassword('bob', user.password);
      expect(result).to.equal(false);
      done();
    });
  });

  describe('#sha256', function() {
    it("should generate a hex digest for sha256 hash ", function(done){
      var result = Cryptish.sha256('bob');
      expect(result).to.equal('81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9');
      done();
    });
  });
});

internals.user = function() {
  return {
    username: "tony",
    displayname: "Anthony Bouch",
    description: "Blah",
    password: 'pbkdf2::I1ZQ5Q==::2000::5EtzqaFwutVGy8tZLITLjz7IarSaShD4vqD1KURUGkPtO3lFiFOvvU3BDaWpssZ7Yd0EWuF1uNmsOiBJyybbpCNgnNGzWZt7sQSzy93WDO+sZ71bi90f9fBNpBDRqT4Z'
  };
};