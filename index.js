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
	lodash = require('lodash'),
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
	this._options = options;
};

_Client.prototype.establish = function () {
	// Generate Diffie-hellman key.
	var clientDH = crypto.getDiffieHellman(this._options.dhGroupName);
	clientDH = generateKeys();

	return request({
		method: this._options.establishMethod, 
		uri: this._options.establishUri
		form: {
			publicKey: clientDH.getPublicKey()
		}
	})
	.spread(function (response, body) {
		if (response.statusCode === 200) {
			var body = JSON.parse(body);

			dhKey = clientDH.computeSecret(body.publicKey, null);
			return dhKey;
		}

		else {
			throw new Error('Server responded http %d.', response.statusCode);
		}
	});
};

_Client.prototype.request = function (requestOptions) {
	var connection = (established)? Promise.resolve() : this.establish();

	return connection
	.then(function () {
		if (!_.isObject(requestOptions.header)) {
			requestOptions.header = {};
		}

		// Create cipher string and replace post body.
		var cipher = crypto.createCipher(this._options.cipherName, this._dhKey);

		var rawData = [
			requestOptions.form || {},
			this._options.password
		];

		cipher.update(JSON.stringify(rawData), 'utf-8');
		
		reqeustOptions.form = {
			cipher: cipher.final('base64')
		};

		requestOptions.header[this._options.requestHeaderName] = ;

		return request(requestOptions);
	});
};



/**
 * Class Server
 */
var _Server = function DHCryptoServer() {

};



module.exports = {
};