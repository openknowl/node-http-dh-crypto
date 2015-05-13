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
	method: 'POST',
	requestHeaderName: 'DH-Authentication',
	ttl: 30,
	// password: string
	// establishUri: uri
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
	// Generate Diffie-hellman key.
	var clientDH = crypto.getDiffieHellman(this._options.dhGroupName);
	clientDH.generateKeys();
	
	var startTime = new Date();

	return request({
		method: this._options.establishMethod, 
		uri: this._options.establishUri,
		form: {
			publicKey: clientDH.getPublicKey()
		}
	})
	.spread(function (response, body) {
		if (response.statusCode === 200) {
			body = JSON.parse(body);

			// Update connection variables.
			this._dhKey = clientDH.computeSecret(body.publicKey, null);
			this._serial = body.serial;
			this._established = true;

			// Set expiry timeout for connection variables..
			if (!_.isNull(this._keyTimeout)) {
				clearTimeout(this._keyTimeout);
			}

			var endTime = new Date();
			var diff = endTime.valueOf() - startTime.valueOf() + 10;

			this._keyTimeout = setTimeout(function () {
				this._established = false;
				this._dhKey = null;
				this._serial = null;
				this._keyTimeout = null;
			}, (body.expires * 1000) - diff);

			// Return Diffie-hellman key and a serial.
			return {
				dhKey: this._dhKey,
				serial: this._serial
			};
		}

		else {
			throw new Error('dh-crypto-server responded with status code %d.', response.statusCode);
		}
	});
};

_Client.prototype.request = function (requestOptions) {
	var connection = (this._established)? Promise.resolve() : this.establish();

	return connection
	.then(function () {
		// Create cipher string and replace post body.
		var cipher = crypto.createCipher(this._options.cipherName, this._dhKey);

		var rawData = [
			requestOptions.form || {},
			this._options.password
		];

		cipher.update(JSON.stringify(rawData), 'utf8');
		
		requestOptions.form = {
			cipher: cipher.final('base64'),
			serial: this._serial
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
};

_Server.prototype.authentication = function authenticationMiddleware(req, res) {
	// Generate Diffie-hellman key.
	var serverDH = crypto.getDiffieHellman(this._options.dhGroupName);
	serverDH.generateKeys();

	var serial = hat.rack();
	
	// Response with public key, serial, and expires.
	res.send({
		publicKey: serverDH.getPublicKey(),
		serial: serial,
		expires: this._options.ttl
	});
	
	process.nextTick(function () {
		// save Diffie-hellman key to cache.
		var dhKey = serverDH.computeSecret(req.body.publicKey, null);
		this._dhKeys.set(serial, dhKey);
	});
};

_Server.prototype.verification = function authenticationMiddleware(req, res, next) {
	var cipherText = req.body.cipher,
		serial = req.body.serial;
	
	if (!cipher || !serial) {
		res.status(400).end();
	}
	
	return this._dhKeys.getAsync(serial)
	.then(function (dhKey) {
		if (_.isUndefined(dhKey)) {
			res.status(401).end();
			return;
		}

		// Decipher cipher text and parse it as JSON.
		var decipher = crypto.createDecipher(this._options.cipherName, dhKey);
		decipher.update(cipherText, 'base64');
		var plainText = decipher.final('utf8');
		var clientMessage = JSON.parse(plainText);

		// Check key.
		if (this._options.password !== clientMessage[1]) {
			res.status(401).end();
			throw new Error();
		}

		// Return original message.
		return clientMessage[0];
	})
	.then(next)
	.catch(next);
};

module.exports = {
	createClient: function (options) {
		return new _Client(options);
	},

	createServer: function (options) {
		return new _Server(options);
	}
};