// authorizationServer.js

var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid};

var ipayload = {};
ipayload.iss = 'http://localhost:9001/';
ipayload.sub = code.user.sub;
ipayload.aud = client.client_id;
ipayload.iat = Math.floor(Date.now() / 1000);
ipayload.exp = Math.floor(Date.now() / 1000) + (5 * 60);	

if (nonce) {
	payload.nonce = nonce;
}

var stringHeader = JSON.stringify(header);
var stringPayload = JSON.stringify(payload);
var privateKey = jose.KEYUTIL.getKey(rsaKey);
var id_token = jose.jws.JWS.sign(rsaKey.alg, stringHeader, stringPayload, privateKey);

console.log('Issuing ID token %s', id_token);


var token_response = { access_token: access_token, token_type: 'Bearer',  scope: cscope, id_token: id_token };


// client.js

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
}

