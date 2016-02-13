var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

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

];

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
		
		requests[reqid] = req.query;
		
		res.render('approve', {client: client, reqid: reqid, scope: rscope});
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
			codes[code] = { authorizationEndpointRequest: query, scope: scope, user: user };
		
			var urlParsed =url.parse(query.redirect_uri);
			delete urlParsed.search; // this is a weird behavior of the URL library
			urlParsed.query = urlParsed.query || {};
			urlParsed.query.code = code;
			urlParsed.query.state = query.state; 
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

	nosql.insert({ access_token: access_token, client_id: clientId, scope: scope, user: user });

	if (refresh_token) {
		nosql.insert({ refresh_token: refresh_token, client_id: clientId, scope: scope, user: user });
	}
	
	console.log('Issuing access token %s', access_token);
	if (refresh_token) {
		console.log('and refresh token %s', refresh_token);
	}
	console.log('with scope %s', access_token, scope);

	var cscope = null;
	if (scope) {
		cscope = scope.join(' ')
	}

	var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token, scope: cscope };

	return token_response;
};

app.post("/token", function(req, res){
	
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
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
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
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

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
