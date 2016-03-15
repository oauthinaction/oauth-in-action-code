// also authorizationServer.js


var ipayload = {};
ipayload.iss = 'http://localhost:9001/';
ipayload.sub = code.user.sub;
ipayload.aud = client.client_id;
ipayload.iat = Math.floor(Date.now() / 1000);
ipayload.exp = Math.floor(Date.now() / 1000) + (5 * 60);	

if (code.request.nonce) {
	ipayload.nonce = code.request.nonce;
}

var istringHeader = JSON.stringify(header);
var istringPayload = JSON.stringify(ipayload);
var privateKey = jose.KEYUTIL.getKey(rsaKey);
var id_token = jose.jws.JWS.sign(rsaKey.alg, istringHeader, istringPayload, privateKey);

console.log('Issuing ID token %s', id_token);


var token_response = { access_token: access_token, token_type: 'Bearer',  scope: cscope, id_token: id_token };

// also client.js

if (body.id_token) {
	console.log('Got ID token: %s', body.id_token);

	// check the id token
	var pubKey = jose.KEYUTIL.getKey(rsaKey);
	var signatureValid = jose.jws.JWS.verify(body.id_token, pubKey, [rsaKey.alg]);
	if (signatureValid) {
		console.log('Signature validated.');
		var tokenParts = body.id_token.split('.');
		var payload = JSON.parse(base64url.decode(tokenParts[1]));
		console.log('Payload', payload);
		if (payload.iss == 'http://localhost:9001/') {
			console.log('issuer OK');
			if ((Array.isArray(payload.aud) && _.contains(payload.aud, client.client_id)) || 
				payload.aud == client.client_id) {
				console.log('Audience OK');

				var now = Math.floor(Date.now() / 1000);

				if (payload.iat <= now) {
					console.log('issued-at OK');
					if (payload.exp >= now) {
						console.log('expiration OK');
		
						console.log('Token valid!');

						// save just the payload, not the container (which has been validated)
						id_token = payload;
		
					}
				}
			}
		}
	}
	res.render('userinfo', {userInfo: userInfo, id_token: id_token});
	
} else {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
}
