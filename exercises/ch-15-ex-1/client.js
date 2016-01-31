var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var jose = require('jsrsasign');
var base64url = require('base64url');


var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token',
	revocationEndpoint: 'http://localhost:9001/revoke',
	registrationEndpoint: 'http://localhost:9001/register',
	userInfoEndpoint: 'http://localhost:9001/userinfo'
};

// client information

var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"],
	"scope": "openid profile email address phone"
};

//var client = {};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var refresh_token = null;
var scope = null;
var key = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, key: key});
});

app.get('/authorize', function(req, res){

	if (!client.client_id) {
		registerClient();
		if (!client.client_id) {
			res.render('error', {error: 'Unable to register client.'});
			return;
		}
	}
	
	access_token = null;
	refresh_token = null;
	scope = null;
	state = randomstring.generate();
	
	var authorizeUrl = url.parse(authServer.authorizationEndpoint, true);
	delete authorizeUrl.search; // this is to get around odd behavior in the node URL library
	authorizeUrl.query.response_type = 'code';
	authorizeUrl.query.scope = client.scope;
	authorizeUrl.query.client_id = client.client_id;
	authorizeUrl.query.redirect_uri = client.redirect_uris[0];
	authorizeUrl.query.state = state;
	
	console.log("redirect", url.format(authorizeUrl));
	res.redirect(url.format(authorizeUrl));
});

var registerClient = function() {
	
	var template = {
		client_name: 'OAuth in Action Dynamic Test Client',
		client_uri: 'http://localhost:9000/',
		redirect_uris: ['http://localhost:9000/callback'],
		grant_types: ['authorization_code'],
		response_types: ['code'],
		token_endpoint_auth_method: 'secret_basic',
		scope: 'openid profile email address phone'
	};

	var headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	};
	
	var regRes = request('POST', authServer.registrationEndpoint, 
		{
			body: JSON.stringify(template),
			headers: headers
		}
	);
	
	if (regRes.statusCode == 201) {
		var body = JSON.parse(regRes.getBody());
		console.log("Got registered client", body);
		if (body.client_id) {
			client = body;
		}
	}
};

app.get("/callback", function(req, res){
	
	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', {error: req.query.error});
		return;
	}
	
	var resState = req.query.state;
	if (resState == state) {
		console.log('State value matches: expected %s got %s', state, resState);
	} else {
		console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
		res.render('error', {error: 'State value did not match'});
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
				grant_type: 'authorization_code',
				code: code,
//				client_id: client.client_id,
//				client_secret: client.client_secret,
				redirect_uri: client.redirect_uri
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

	console.log('Requesting access token for code %s',code);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}
		
		scope = body.scope;
		console.log('Got scope: %s', scope);

		key = body.access_token_key;
		console.log('Got key: %O', key);

		res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, key: key});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});

app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
		if (refresh_token) {
			// try to refresh and start again
			refreshAccessToken(req, res);
			return;
		} else {
			res.render('error', {error: 'Missing access token.'});
			return;
		}
	}
	
	console.log('Making request with access token %s', access_token);
	
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
	//var access_token = jose.jws.JWS.sign('HS256', stringHeader, stringPayload, new Buffer(sharedTokenSecret).toString('hex'));
	var privateKey = jose.KEYUTIL.getKey(rsaKey);
	var access_token = jose.jws.JWS.sign('RS256', stringHeader, stringPayload, privateKey);
	*/
	
	var header = { 'typ': 'PoP', 'alg': 'RS256', 'kid': key.kid };
	
	var payload = {};
	payload.at = access_token;
	payload.ts = Math.floor(Date.now() / 1000);
	payload.m = 'POST';
	payload.u = 'localhost:9002';
	payload.p = '/resource';
	
	// TODO: header calculation
	
	var stringHeader = JSON.stringify(header);
	var stringPayload = JSON.stringify(payload);
	var privateKey = jose.KEYUTIL.getKey(key);
	var signed = jose.jws.JWS.sign('RS256', stringHeader, stringPayload, privateKey);

	console.log('Signed PoP header %s', signed);
	
	var headers = {
		'Authorization': 'PoP ' + signed,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('POST', protectedResource,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('data', {resource: body});
		return;
	} else {
		access_token = null;
		if (refresh_token) {
			// try to refresh and start again
			refreshAccessToken(req, res);
			return;
		} else {
			res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
			return;
		}
	}
	
	
});

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
