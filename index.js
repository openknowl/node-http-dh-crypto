/**
 * node-http-dh-crypto
 * https://github.com/openknowl/node-http-dh-crypto
 *
 * Copyright (c) 2015 OPENKNOWL
 * Licensed under the MIT license.
 */

// Internal libraries.
var crypto = require('crypto'),
	http = require('http'),
	https = require('https'),
	util = require('util');

// External libraries.
var Promise = require('bluebird'),
	_ = require('lodash'),
	hat = require('hat'),
	NodeCache = require('node-cache'),
	request = Promise.promisify(require('request'));

Promise.promisifyAll(NodeCache.prototype);

// Options
var defaultOptions = {
	dhGroupName: 'modp5',
	cipherName: 'des-cbc',
	//host: 'http://localhost:3000',
	//establishPath: '/api/establish',
	establishMethod: 'POST',
	requestHeaderName: 'DH-Authentication',
	ttl: 30,
	//password: 'password'
};

/**
 * Class Client
 */
var _Client = function DHCryptoClient(options) {
	this._established = false;
	this._dhKey = null;
	this._serial = null;
	this._options = _.defaults(options, defaultOptions);
	this._keyTimeout = null;
};

_Client.prototype.establish = function () {
	var _this = this;

	// Generate Diffie-hellman key.
	var clientDH = crypto.getDiffieHellman(_this._options.dhGroupName);
	clientDH.generateKeys();
	
	var startTime = new Date();

	return request({
		method: _this._options.establishMethod, 
		uri: _this._options.host + _this._options.establishPath,
		form: {
			publicKey: clientDH.getPublicKey('base64')
		}
	})
	.spread(function (response, body) {
		if (response.statusCode === 200) {
			body = JSON.parse(body);

			// Update connection variables.
			_this._dhKey = clientDH.computeSecret(body.publicKey, 'base64', 'base64');
			_this._serial = body.serial;
			_this._established = true;

			// Set expiry timeout for connection variables..
			if (!_.isNull(_this._keyTimeout)) {
				clearTimeout(_this._keyTimeout);
			}

			var endTime = new Date();
			var diff = endTime.valueOf() - startTime.valueOf() + 10;

			_this._keyTimeout = setTimeout(function () {
				_this._established = false;
				_this._dhKey = null;
				_this._serial = null;
				_this._keyTimeout = null;
			}, (body.expires * 1000) - diff);

			// Return Diffie-hellman key and a serial.
			return {
				dhKey: _this._dhKey,
				serial: _this._serial
			};
		}

		else {
			throw new Error('dh-crypto-server responded with status code %d.', response.statusCode);
		}
	});
};

_Client.prototype.request = function (requestOptions) {
	var _this = this;
	
	var connection = (_this._established)? Promise.resolve() : _this.establish();

	return connection
	.then(function () {
		requestOptions.uri = _this._options.host + requestOptions.path;

		// Create cipher string and replace post body.
		var cipher = crypto.createCipher(_this._options.cipherName, _this._dhKey);

		var rawData = [
			requestOptions.form || {},
			_this._options.password
		];

		var cipherText = cipher.update(JSON.stringify(rawData), 'utf8', 'base64');
		cipherText += cipher.final('base64');
		
		requestOptions.form = {
			cipher: cipherText,
			serial: _this._serial
		};

		// Send request with these options.
		return request(requestOptions);
	});
};

/**
 * Class Server
 */
var _Server = function DHCryptoServer(options) {
	this._options = _.defaults(options, defaultOptions);
	this._dhKeys = new NodeCache({
		stdTTL: this._options.ttl, 
		checkperiod: this._options.ttl
	});
	this._serialRack = hat.rack();
};

_Server.prototype.authentication = function () {
	var _this = this;
	return function authenticationMiddleware(req, res, next) {
		// Generate Diffie-hellman key.
		var serverDH = crypto.getDiffieHellman(_this._options.dhGroupName);
		serverDH.generateKeys();
	
		var serial = _this._serialRack();

		// Response with public key, serial, and expires.
		res.send({
			publicKey: serverDH.getPublicKey('base64'),
			serial: serial,
			expires: _this._options.ttl
		});
		
		process.nextTick(function () {
			// save Diffie-hellman key to cache.
			var dhKey = serverDH.computeSecret(req.body.publicKey, 'base64', 'base64');
			_this._dhKeys.set(serial, dhKey);
			next();
		});
	};
};

_Server.prototype.verification = function () {
	var _this = this;
	return function authenticationMiddleware(req, res, next) {
		var cipherText = req.body.cipher,
			serial = req.body.serial;
		
		if (!cipherText || !serial) {
			res.status(400).end();
		}
		
		return _this._dhKeys.getAsync(serial)
		.then(function (dhKey) {
			if (_.isUndefined(dhKey)) {
				res.status(401).end();
				return;
			}
	
			// Decipher cipher text and parse it as JSON.
			var decipher = crypto.createDecipher(_this._options.cipherName, dhKey);
			var plainText = decipher.update(cipherText, 'base64', 'utf8');
			plainText += decipher.final('utf8');
			var clientMessage = JSON.parse(plainText);

			// Check key.
			if (_this._options.password !== clientMessage[1]) {
				res.status(401).end();
				throw new Error();
			}
	
			// Return original message.
			req.body = clientMessage[0];
			next();
		})
		.catch(next);
	};
};

module.exports = {
	createClient: function (options) {
		return new _Client(options);
	},

	createServer: function (options) {
		return new _Server(options);
	}
};