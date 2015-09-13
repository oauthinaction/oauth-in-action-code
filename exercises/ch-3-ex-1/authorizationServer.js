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
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "foo bar"
	}
];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
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

				var access_token = randomstring.generate();

				var cscope = null;
				if (code.scope) {
					cscope = code.scope.join(' ')
				}

				nosql.insert({ access_token: access_token, client_id: clientId, scope: cscope });

				console.log('Issuing access token %s', access_token);
				console.log('with scope %s', cscope);

				var token_response = { access_token: access_token, token_type: 'Bearer',  scope: cscope };

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

app.use('/', express.static('files/authorizationServer'));

// clear the database on startup
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
