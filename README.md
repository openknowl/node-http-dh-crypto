# node-http-dh-crypto

## How it works

1. CLIENT generates diffie-hellman key and requests SERVER with the public key.
2. SERVER generates diffie-hellman key and calculates cipher key using CLIENT's public key.
3. SERVER returns its public key and `id` to CLIENT.
4. CLIENT calculates cipher key with SERVER's public key. Both SERVER and CLIENT shares temporary key for ciphers.
5. CLIENT requests its `id`, and a cipher text encrypting the pre-exchanged password and the message.
6. SERVER deciphers the cipher text and verify the password.
7. If password is correct, SERVER tosses the message to next middleware chain.

## Examples

### Client

```js
var dhCrypto = require('node-http-dh-crypto');
var bodyParser = require('body-parser');

var dhCryptoClient = dhCrypto.createClient({
	password: 'the_cake_is_a_lie!',
	host: 'http://localhost:3001',
	establishPath: '/api/establish',
	establishMethod: 'POST'
});

app.get('/ping', function (req, res) {
	dhCryptoClient.request({
		path: '/ping',
		method: 'post',
		form: {
			ping: 416
		}
	})
	.then(function (response) {
		console.log(response);
	});
});
```

### Server

```js
var dhCrypto = require('node-http-dh-crypto');
var bodyParser = require('body-parser');

var dhCryptoServer = dhCrypto.createServer({
	password: 'the_cake_is_a_lie!',
	ttl: 120,
});

app.use(bodyParser.urlencoded({ extended: false }));

app.post('/establish', dhCryptoServer.authentication());

app.post('/ping', dhCryptoServer.verification(), function (req, res) {
	res.json({
		pong: req.body.ping
	});
});
```

The client will be responded `{ pong: 416 }`.

## License 
Licensed MIT, Copyright (c) 2015 OPENKNOWL Inc.