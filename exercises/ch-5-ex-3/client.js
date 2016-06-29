var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
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

var rsaKey = {
  "alg": "RS256",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

// client information

var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"],
	"scope": "foo bar"
};

//var client = {};

var protectedResource = 'http://localhost:9002/resource';
var wordApi = 'http://localhost:9002/words';
var produceApi = 'http://localhost:9002/produce';
var favoritesApi = 'http://localhost:9002/favorites';

var state = null;

var access_token = null;
var refresh_token = null;
var scope = null;
var id_token = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.get('/authorize', function(req, res){

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

		res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});

var refreshAccessToken = function(req, res) {
	var form_data = qs.stringify({
				grant_type: 'refresh_token',
				refresh_token: refresh_token,
				client_id: client.client_id,
				client_secret: client.client_secret,
				redirect_uri: client.redirect_uri
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	console.log('Refreshing token %s', refresh_token);
	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);
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
	
		// try again
		res.redirect('/fetch_resource');
		return;
	} else {
		console.log('No refresh token, asking the user to get a new access token');
		// tell the user to get a new access token
		res.redirect('/authorize');
		return;
	}
};

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
		res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
		return;
	}
	
});

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
