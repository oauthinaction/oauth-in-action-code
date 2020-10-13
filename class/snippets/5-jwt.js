var header = { 
	typ: 'JWT', 
	alg: rsaKey.alg, 
	kid: rsaKey.kid
};

var payload = {
	iss: 'http://localhost:9001/',
	sub: code.user ? code.user.sub : null,
	aud: 'http://localhost:9002/',
	iat: Math.floor(Date.now() / 1000),
	exp: Math.floor(Date.now() / 1000) + (5 * 60),
	jti: randomstring.generate(8)
};

console.log(payload);

var stringHeader = JSON.stringify(header);
var stringPayload = JSON.stringify(payload);
//var encodedHeader = base64url.encode(JSON.stringify(header));
//var encodedPayload = base64url.encode(JSON.stringify(payload));

//var access_token = encodedHeader + '.' + encodedPayload + '.';
//var access_token = jose.jws.JWS.sign('HS256', stringHeader, stringPayload, Buffer.from(sharedTokenSecret).toString('hex'));

var privateKey = jose.KEYUTIL.getKey(rsaKey);
var access_token = jose.jws.JWS.sign(rsaKey.alg, stringHeader, stringPayload, privateKey);
