var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");

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
	"scope": "read write delete"
};

var wordApi = 'http://localhost:9002/words';

var state = null;

var access_token = null;
var refresh_token = null;
var scope = null;

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
				redirect_uri: client.redirect_uri
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + Buffer.from(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
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

app.get('/words', function (req, res) {
	res.render('words', {words: '', timestamp: 0, result: 'noget'});
	return;
});

app.get('/get_words', function (req, res) {

	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('GET', wordApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('words', {words: body.words, timestamp: body.timestamp, result: 'get'});
		return;
	} else {
		res.render('words', {words: '', timestamp: 0, result: 'noget'});
		return;
	}
	
	
	
});

app.get('/add_word', function (req, res) {
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var form_body = qs.stringify({word: req.query.word});
	
	var resource = request('POST', wordApi,
		{headers: headers, body: form_body}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		res.render('words', {words: '', timestamp: 0, result: 'add'});
		return;
	} else {
		res.render('words', {words: '', timestamp: 0, result: 'noadd'});
		return;
	}
	

});

app.get('/delete_word', function (req, res) {

	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('DELETE', wordApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		res.render('words', {words: '', timestamp: 0, result: 'rm'});
		return;
	} else {
		res.render('words', {words: '', timestamp: 0, result: 'norm'});
		return;
	}
	
	
});


app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
