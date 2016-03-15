var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid};

var payload = {};
payload.iss = 'http://localhost:9001/';
payload.sub = code.user.sub;
payload.aud = 'http://localhost:9002/';
payload.iat = Math.floor(Date.now() / 1000);
payload.exp = Math.floor(Date.now() / 1000) + (5 * 60);
payload.jti = randomstring.generate();
console.log(payload);

var stringHeader = JSON.stringify(header);
var stringPayload = JSON.stringify(payload);
//var encodedHeader = base64url.encode(JSON.stringify(header));
//var encodedPayload = base64url.encode(JSON.stringify(payload));

//var access_token = encodedHeader + '.' + encodedPayload + '.';
//var access_token = jose.jws.JWS.sign('HS256', stringHeader, stringPayload, new Buffer(sharedTokenSecret).toString('hex'));

var privateKey = jose.KEYUTIL.getKey(rsaKey);
var access_token = jose.jws.JWS.sign(rsaKey.alg, stringHeader, stringPayload, privateKey);
