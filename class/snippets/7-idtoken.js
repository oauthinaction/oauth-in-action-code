// also authorizationServer.js

var token_response = { access_token: access_token, token_type: 'Bearer',  scope: cscope };

if (__.contains(code.scope, 'openid')) {
	var ipayload = {
		iss: 'http://localhost:9001/',
		sub: code.user.sub,
		aud: client.client_id,
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + (5 * 60)	
	};
	if (code.request.nonce) {
		ipayload.nonce = code.request.nonce;
	}

	var istringHeader = JSON.stringify(header);
	var istringPayload = JSON.stringify(ipayload);
	var privateKey = jose.KEYUTIL.getKey(rsaKey);
	var id_token = jose.jws.JWS.sign(rsaKey.alg, istringHeader, istringPayload, privateKey);

	console.log('Issuing ID token %s', id_token);

	token_response.id_token = id_token;

}

// also client.js

if (body.id_token) {
	userInfo = null;
	id_token = null;
	
	console.log('Got ID token: %s', body.id_token);

	// check the id token
	var tokenParts = body.id_token.split('.');
	var header = JSON.parse(base64url.decode(tokenParts[0]));
	var payload = JSON.parse(base64url.decode(tokenParts[1]));

	console.log('Payload', payload);

	var pubKey = 
	if (jose.jws.JWS.verify(body.id_token, 
		jose.KEYUTIL.getKey(rsaKey), 
		[header.alg])) {

		console.log('Signature validated.');
		if (payload.iss == 'http://localhost:9001/') {
			console.log('issuer OK');
			if ((Array.isArray(payload.aud) && __.contains(payload.aud, client.client_id)) || 
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
	return;
}