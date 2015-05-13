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
	NodeCache = require('node-cache'),
	request = Promise.promisify(require('request'));

// Options
var defaultOptions = {
	dhGroupName: 'modp5',
	cipherName: 'des-cbc',
	method: 'POST',
	requestHeaderName: 'DH-Authentication'
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

		cipher.update(JSON.stringify(rawData), 'utf-8');
		
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
	this._dhKeys = null;
	this._options = _.defaults(options, defaultOptions);
};

_Server.prototype.authentication = function () {
	
};

_Server.prototype.verification = function () {
	
};

module.exports = {
	createClient: function (options) {
		return new _Client(options);
	},

	createServer: function (options) {
		return new _Server(options);
	}
};