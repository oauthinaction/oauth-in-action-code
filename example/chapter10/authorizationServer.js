var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var qs = require("qs");
var __ = require('underscore');
__.string = require('underscore.string');
var base64url = require('base64url');
var jose = require('jsrsasign');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "openid profile email phone address"
	},
	{
		"client_id": "oauth-client-2",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "bar"
	},
	{
		"client_id": "native-client-1",
		"client_secret": "oauth-native-secret-1",
		"redirect_uris": ["mynativeapp://"],
		"scope": "openid profile email phone address"
	}
];

var sharedTokenSecret = "shared token secret!";

var rsaKey = {
  "alg": "RS256",
  "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

var protectedResources = [
	{
		"resource_id": "protected-resource-1",
		"resource_secret": "protected-resource-secret-1"
	}
];

var userInfo = {

	"alice": {
		"sub": "9XE3-JI34-00132A",
		"preferred_username": "alice",
		"name": "Alice",
		"email": "alice.wonderland@example.com",
		"email_verified": true
	},
	
	"bob": {
		"sub": "1ZT5-OE63-57383B",
		"preferred_username": "bob",
		"name": "Bob",
		"email": "bob.loblob@example.net",
		"email_verified": false
	},

	"carol": {
		"sub": "F5Q1-L6LGG-959FS",
		"preferred_username": "carol",
		"name": "Carol",
		"email": "carol.lewis@example.net",
		"email_verified": true,
		"username" : "clewis",
		"password" : "user password!"
 	}	
};

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

var getProtectedResource = function(resourceId) {
	return __.find(protectedResources, function(resource) { return resource.resource_id == resourceId; });
};


var getUser = function(username) {
	return __.find(userInfo, function (user, key) { return user.username == username; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){
	
	var client = getClient(req.query.client_id);
	
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {
		
		var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(rscope, cscope).length > 0) {
			// client asked for a scope it couldn't have
			var urlParsed = url.parse(req.query.redirect_uri);
			delete urlParsed.search; // this is a weird behavior of the URL library
			urlParsed.query = urlParsed.query || {};
			urlParsed.query.error = 'invalid_scope';
			res.redirect(url.format(urlParsed));
			return;
		}
		
		var reqid = randomstring.generate(8);
		var code_challenge = req.query.code_challenge;
		
		requests[reqid] = req.query;
		
		res.render('approve', {client: client, reqid: reqid, scope: rscope, code_challenge: code_challenge});
		return;
	}

});

app.post('/approve', function(req, res) {

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render('error', {error: 'No matching authorization request'});
		return;
	}
	
	if (req.body.approve) {
		if (query.response_type == 'code') {
			// user approved access
			var code = randomstring.generate(8);
			
			var user = req.body.user;
			var code_challenge = req.body.code_challenge;
		
			var scope = __.filter(__.keys(req.body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(scope, cscope).length > 0) {
				// client asked for a scope it couldn't have
				var urlParsed = url.parse(query.redirect_uri);
				delete urlParsed.search; // this is a weird behavior of the URL library
				urlParsed.query = urlParsed.query || {};
				urlParsed.query.error = 'invalid_scope';
				res.redirect(url.format(urlParsed));
				return;
			}

			// save the code and request for later
			codes[code] = { authorizationEndpointRequest: query, scope: scope, user: user, code_challenge:code_challenge };
		
			var urlParsed =url.parse(query.redirect_uri);
			delete urlParsed.search; // this is a weird behavior of the URL library
			urlParsed.query = urlParsed.query || {};
			urlParsed.query.code = code;
			urlParsed.query.state = query.state; 
			res.redirect(url.format(urlParsed));
			return;
		} else if (query.response_type == 'token') {
			var user = req.body.user;
		
			var scope = __.filter(__.keys(req.body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(scope, cscope).length > 0) {
				// client asked for a scope it couldn't have
				var urlParsed = url.parse(query.redirect_uri);
				delete urlParsed.search; // this is a weird behavior of the URL library
				urlParsed.query = urlParsed.query || {};
				urlParsed.query.error = 'invalid_scope';
				res.redirect(url.format(urlParsed));
				return;
			}

			var user = userInfo[user];
			if (!user) {		
				console.log('Unknown user %s', user)
				res.status(500).render('error', {error: 'Unknown user ' + user});
				return;
			}
	
			console.log("User %j", user);

			var token_response = generateTokens(req, res, query.clientId, user, cscope);		

			var urlParsed = url.parse(query.redirect_uri);
			delete urlParsed.search; // this is a weird behavior of the URL library
			if (query.state) {
				token_response.state = query.state;
			} 				
			urlParsed.hash = qs.stringify(token_response);
			res.redirect(url.format(urlParsed));
			return;

		} else {
			// we got a response type we don't understand
			var urlParsed =url.parse(query.redirect_uri);
			delete urlParsed.search; // this is a weird behavior of the URL library
			urlParsed.query = urlParsed.query || {};
			urlParsed.query.error = 'unsupported_response_type';
			res.redirect(url.format(urlParsed));
			return;
		}
	} else {
		// user denied access
		var urlParsed =url.parse(query.redirect_uri);
		delete urlParsed.search; // this is a weird behavior of the URL library
		urlParsed.query = urlParsed.query || {};
		urlParsed.query.error = 'access_denied';
		res.redirect(url.format(urlParsed));
		return;
	}
	
});

var generateTokens = function (req, res, clientId, user, scope, nonce, generateRefreshToken) {
	var access_token = randomstring.generate();

	var refresh_token = null;

	if (generateRefreshToken) {
		refresh_token = randomstring.generate();	
	}	

	/*
	var header = { 'typ': 'JWT', 'alg': 'RS256', 'kid': 'authserver'};

	var payload = {};
	payload.iss = 'http://localhost:9001/';
	payload.sub = user;
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
	//var access_token = jose.jws.JWS.sign('HS256', stringHeader, stringPayload, Buffer.from(sharedTokenSecret).toString('hex'));
	var privateKey = jose.KEYUTIL.getKey(rsaKey);
	var access_token = jose.jws.JWS.sign('RS256', stringHeader, stringPayload, privateKey);
	*/

	var header = { 'typ': 'JWT', 'alg': 'RS256', 'kid': 'authserver'};
	
	var payload = {};
	payload.iss = 'http://localhost:9001/';
	payload.sub = user.sub;
	payload.aud = clientId;
	payload.iat = Math.floor(Date.now() / 1000);
	payload.exp = Math.floor(Date.now() / 1000) + (5 * 60);	

	if (nonce) {
		payload.nonce = nonce;
	}

	var stringHeader = JSON.stringify(header);
	var stringPayload = JSON.stringify(payload);
	var privateKey = jose.KEYUTIL.getKey(rsaKey);
	var id_token = jose.jws.JWS.sign('RS256', stringHeader, stringPayload, privateKey);

	nosql.insert({ access_token: access_token, client_id: clientId, scope: scope, user: user });

	if (refresh_token) {
		nosql.insert({ refresh_token: refresh_token, client_id: clientId, scope: scope, user: user });
	}
	
	console.log('Issuing access token %s', access_token);
	if (refresh_token) {
		console.log('and refresh token %s', refresh_token);
	}
	console.log('with scope %s', access_token, scope);
	console.log('Iussing ID token %s', id_token);

	var cscope = null;
	if (scope) {
		cscope = scope.join(' ')
	}

	var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token, scope: cscope, id_token: id_token };

	return token_response;
};

app.post("/token", function(req, res){
	
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
		var clientId = querystring.unescape(clientCredentials[0]);
		var clientSecret = querystring.unescape(clientCredentials[1]);
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (req.body.grant_type == 'authorization_code') {
		
		var code = codes[req.body.code];
		
		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.authorizationEndpointRequest.client_id == clientId) {

				console.log("code challenge %s", code.code_challenge);
				if (code.code_challenge) {
					if (code.code_challenge != req.body.code_verifier ) {
						res.status(400).json({error: 'iInvalid code verifier'});
						return;
					}
				}

				var user = userInfo[code.user];
				if (!user) {		
					console.log('Unknown user %s', user)
					res.status(500).render('error', {error: 'Unknown user ' + code.user});
					return;
				}	
				console.log("User %j", user);

				var token_response = generateTokens(req, res, clientId, user, code.scope, code.authorizationEndpointRequest.nonce, true);

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);
				
				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.authorizationEndpointRequest.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
	} else if (req.body.grant_type == 'client_credentials') {
		var scope = req.body.scope ? req.body.scope.split(' ') : undefined;
		var client = getClient(query.client_id);
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(scope, cscope).length > 0) {
			// client asked for a scope it couldn't have
			res.status(400).json({error: 'invalid_scope'});
			return;
		}

		var access_token = randomstring.generate();
		var token_response = { access_token: access_token, token_type: 'Bearer', scope: scope.join(' ') };
		nosql.insert({ access_token: access_token, client_id: clientId, scope: scope });
		console.log('Issuing access token %s', access_token);
		res.status(200).json(token_response);
		return;	
		
	} else if (req.body.grant_type == 'refresh_token') {
	nosql.find().make(function(builder) {
	  builder.where('refresh_token', req.body.refresh_token);
	  builder.callback(function(err, tokens) {
			if (tokens.length == 1) {
				var token = tokens[0];
				if (token.client_id != clientId) {
					console.log('Invalid client using a refresh token, expected %s got %s', token.client_id, clientId);
					nosql.remove().make(function(builder) { builder.where('refresh_token', req.body.refresh_token); });
					res.status(400).end();
					return
				}
				console.log("We found a matching token: %s", req.body.refresh_token);
				var access_token = randomstring.generate();
				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: req.body.refresh_token };
				nosql.insert({ access_token: access_token, client_id: clientId });
				console.log('Issuing access token %s for refresh token %s', access_token, req.body.refresh_token);
				res.status(200).json(token_response);
				return;
			} else {
				console.log('No matching token was found.');
				res.status(401).end();
			}
	  })
	});
	} else if (req.body.grant_type == 'password') {
		var username = req.body.username;
		var user = getUser(username);
		if (!user) {
			console.log('Unknown user %s', user);
			res.status(401).json({error: 'invalid_grant'});
			return;
		}
		console.log("user is %j ", user)
		
		var password = req.body.password;
		if (user.password != password) {
			console.log('Mismatched resource owner password, expected %s got %s', user.password, password);
			res.status(401).json({error: 'invalid_grant'});
			return;
		}

		var scope = req.body.scope;

		var token_response = generateTokens(req, res, clientId, user, scope);
		
		res.status(200).json(token_response);		
		return;
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

app.post('/revoke', function(req, res) {
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
		var clientId = querystring.unescape(clientCredentials[0]);
		var clientSecret = querystring.unescape(clientCredentials[1]);
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	var inToken = req.body.token;
  nosql.remove().make(function(builder) {
    builder.and();
    builder.where('access_token', inToken);
    builder.where('client_id', clientId);
    builder.callback(function(err, count) {
      console.log("Removed %s tokens", count);
      res.status(204).end();
      return;
    });
  });
	
});

app.post('/introspect', function(req, res) {
	var auth = req.headers['authorization'];
	var resourceCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var resourceId = querystring.unescape(resourceCredentials[0]);
	var resourceSecret = querystring.unescape(resourceCredentials[1]);

	var resource = getProtectedResource(resourceId);
	if (!resource) {
		console.log('Unknown resource %s', resourceId);
		res.status(401).end();
		return;
	}
	
	if (resource.resource_secret != resourceSecret) {
		console.log('Mismatched secret, expected %s got %s', resource.resource_secret, resourceSecret);
		res.status(401).end();
		return;
	}
	
	var inToken = req.body.token;
	console.log('Introspecting token %s', inToken);
	nosql.one().make(function(builder) {
	  builder.where('access_token', inToken);
	  builder.callback(function(err, token) {
	    if (token) {
			console.log("We found a matching token: %s", inToken);
			
			var introspectionResponse = {};
			introspectionResponse.active = true;
			introspectionResponse.iss = 'http://localhost:9001/';
			introspectionResponse.sub = token.user;
			introspectionResponse.scope = token.scope.join(' ');
			introspectionResponse.client_id = token.client_id;
						
			res.status(200).json(introspectionResponse);
			return;
	    } else {
			console.log('No matching token was found.');

			var introspectionResponse = {};
			introspectionResponse.active = false;
			res.status(200).json(introspectionResponse);
			return;
	    };
	  })
	});
	
	
});

var checkClientMetadata = function (req, res) {
	var reg = {};

	if (!req.body.token_endpoint_auth_method) {
		reg.token_endpoint_auth_method = 'secret_basic';	
	} else {
		reg.token_endpoint_auth_method = req.body.token_endpoint_auth_method;
	}
	
	if (!__.contains(['secret_basic', 'secret_post', 'none'], reg.token_endpoint_auth_method)) {
		res.status(400).json({error: 'invalid_client_metadata'});
		return;
	}
	
	if (!req.body.grant_types) {
		if (!req.body.response_types) {
			reg.grant_types = ['authorization_code'];
			reg.response_types = ['code'];
		} else {
			reg.response_types = req.body.response_types;
			if (__.contains(req.body.response_types, 'code')) {
				reg.grant_types = ['authorization_code'];
			} else {
				reg.grant_types = [];
			}
		}
	} else {
		if (!req.body.response_types) {
			reg.grant_types = req.body.grant_types;
			if (__.contains(req.body.grant_types, 'authorization_code')) {
				reg.response_types =['code'];
			} else {
				reg.response_types = [];
			}
		} else {
			reg.grant_types = req.body.grant_types;
			reg.reponse_types = req.body.response_types;
			if (__.contains(req.body.grant_types, 'authorization_code') && !__.contains(req.body.response_types, 'code')) {
				reg.response_types.push('code');
			}
			if (!__.contains(req.body.grant_types, 'authorization_code') && __.contains(req.body.response_types, 'code')) {
				reg.grant_types.push('authorization_code');
			}
		}
	}

	if (!__.isEmpty(__.without(reg.grant_types, 'authorization_code', 'refresh_token')) ||
		!__.isEmpty(__.without(reg.response_types, 'code'))) {
		res.status(400).json({error: 'invalid_client_metadata'});
		return;
	}

	if (!req.body.redirect_uris || !__.isArray(req.body.redirect_uris) || __.isEmpty(req.body.redirect_uris)) {
		res.status(400).json({error: 'invalid_redirect_uri'});
		return;
	} else {
		reg.redirect_uris = req.body.redirect_uris;
	}
	
	if (typeof(req.body.client_name) == 'string') {
		reg.client_name = req.body.client_name;
	}
	
	if (typeof(req.body.client_uri) == 'string') {
		reg.client_uri = req.body.client_uri;
	}
	
	if (typeof(req.body.logo_uri) == 'string') {
		reg.logo_uri = req.body.logo_uri;
	}
	
	if (typeof(req.body.scope) == 'string') {
		reg.scope = req.body.scope;
	}
	
	return reg;
};

app.post('/register', function (req, res){

	var reg = checkClientMetadata(req, res);
	if (!reg) {
		return;
	}

	reg.client_id = randomstring.generate();
	if (__.contains(['client_secret_basic', 'client_secret_post']), reg.token_endpoint_auth_method) {
		reg.client_secret = randomstring.generate();
	}

	reg.client_id_created_at = Math.floor(Date.now() / 1000);
	reg.client_secret_expires_at = 0;

	reg.registration_access_token = randomstring.generate();
	reg.registration_client_uri = 'http://localhost:9001/register/' + reg.client_id;

	clients.push(reg);
	
	res.status(201).json(reg);
	return;
});

var validateConfigurationEndpointRequest = function (req, res, next) {
	var clientId = req.params.clientId;
	var client = getClient(clientId);
	if (!client) {
		res.status(404).end();
		return;
	}

	var auth = req.headers['authorization'];
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		var regToken = auth.slice('bearer '.length);

		if (regToken == client.registration_access_token) {
			req.client = client;
			next();
			return;
		} else {
			res.status(403).end();
			return;
		}
		
	} else {
		res.status(401).end();
		return;
	}

};

app.get('/register/:clientId', validateConfigurationEndpointRequest, function(req, res) {
	res.status(200).json(client);
});

app.put('/register/:clientId', validateConfigurationEndpointRequest, function(req, res) {

	if (req.body.client_id != client.client_id) {
		res.status(400).json({error: 'invalid_client_metadata'});
		return;
	}
	
	if (req.body.client_secret && req.body.client_secret != client.client_secret) {
		res.status(400).json({error: 'invalid_client_metadata'});
	}

	var reg = checkClientMetadata(req, res);
	if (!reg) {
		return;
	}

	__.each(client, function(value, key, list) {
		client[key] = reg[key];
	});
	__.each(reg, function(value, key, list) {
		client[key] = reg[key];
	});

	res.status(200).json(client);
	
});

app.delete('/register/:clientId', validateConfigurationEndpointRequest, function(req, res) {
	clients = __.reject(clients, __.matches({client_id: client.client_id}));

  nosql.remove().make(function(builder) {
    builder.where('client_id', clientId);
    builder.callback(function(err, count) {
      console.log("Removed %s tokens", count);
    });
  });
	
	res.status(204).end();
	return;

	
});

var getAccessToken = function(req, res, next) {
	// check the auth header first
	var auth = req.headers['authorization'];
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
		// not in the header, check in the form body
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}
	
	console.log('Incoming token: %s', inToken);
	nosql.one().make(function(builder) {
	  builder.where('access_token', inToken);
	  builder.callback(function(err, token) {
	    if (token) {
	      console.log("We found a matching token: %s", inToken);
	    } else {
	      console.log('No matching token was found.');
	    };
	    req.access_token = token;
	    next();
	    return;
	  });
	});
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};

var userInfoEndpoint = function(req, res) {
	
	if (!__.contains(req.access_token.scope, 'openid')) {
		res.status(403).end();
		return;
	}
	
	var user = userInfo[req.access_token.user];
	if (!user) {
		res.status(404).end();
		return;
	}
	
	var out = {};
	__.each(req.access_token.scope, function (scope) {
		if (scope == 'openid') {
			__.each(['sub'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'profile') {
			__.each(['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'email') {
			__.each(['email', 'email_verified'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'address') {
			__.each(['address'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'phone') {
			__.each(['phone_number', 'phone_number_verified'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		}
	});
	
	res.status(200).json(out);
	return;
};

app.get('/userinfo', getAccessToken, requireAccessToken, userInfoEndpoint);
app.post('/userinfo', getAccessToken, requireAccessToken, userInfoEndpoint);

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
