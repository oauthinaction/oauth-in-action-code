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
var __ = require('underscore');
__.string = require('underscore.string');


var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// client information

var client = {};

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token',
	registrationEndpoint: 'http://localhost:9001/register'
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var refresh_token = null;
var scope = null;
var id_token = null;
var userInfo = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, client: client});
});

app.get('/authorize', function(req, res){
	
	/*
	 * If the client hasn't been registered yet, call the registerClient function
	 */

	access_token = null;
	refresh_token = null;
	scope = null;
	state = randomstring.generate();
	
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		scope: client.scope,
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	});
	
	console.log("redirect", authorizeUrl);
	res.redirect(authorizeUrl);
});

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
				redirect_uri: client.redirect_uris[0]
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
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

		res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, client: client});

	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});

app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}
	
	console.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
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

var registerClient = function() {
	
	/*
	 * Call the registration endpoint with your desired client information and save the results
	 */
	
};

app.use('/', express.static('files/client'));

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var encodeClientCredentials = function(clientId, clientSecret) {
	return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
