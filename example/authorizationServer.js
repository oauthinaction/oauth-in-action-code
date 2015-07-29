var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');

var app = express();

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
var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uri": "http://localhost:9000/callback",
	"scope": "foo"
};

var code = null;

app.get('/', function(req, res) {
	res.render('index', {client: client, authServer: authServer});
});

app.get("/authorize", function(req, res){
	
	if (req.query.client_id == client.client_id && req.query.redirect_uri == client.redirect_uri) {

		res.render('approve', {params: req.query, client: client});
		return;
	} else {
		console.log('Unknown client, expected %s got %s', client.client_id, req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	}

});

app.post('/approve', function(req, res) {
	
	if (req.body.approve) {
		// user approved access
		code = randomstring.generate(8);

		var urlParsed =url.parse(req.body.redirect_uri);
		delete urlParsed.search; // this is a weird behavior of the URL library
		urlParsed.query = urlParsed.query || {};
		urlParsed.query.code = code;
		urlParsed.query.state = req.body.state; 
		res.redirect(url.format(urlParsed));
	} else {
		// user denied access
		var urlParsed =url.parse(req.body.redirect_uri);
		delete urlParsed.search; // this is a weird behavior of the URL library
		urlParsed.query = urlParsed.query || {};
		urlParsed.query.error = 'access_denied';
		res.redirect(url.format(urlParsed));
	}
	
});

app.post("/token", function(req, res){
	
	if (req.body.client_id == client.client_id && req.body.client_secret == client.client_secret) {
		if (req.body.grant_type == 'authorization_code') {
			if (req.body.code == code) {
				code = null; // burn our code, it's been used
				var refresh_token = randomstring.generate();
				var access_token = randomstring.generate();
				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token };
				nosql.insert({ access_token: access_token, client_id: req.body.client_id });
				nosql.insert({ refresh_token: refresh_token, client_id: req.body.client_id });
				console.log('Issuing access token %s and refresh token %s for code %s', access_token, refresh_token, req.body.code);
				res.status(200).json(token_response);
				return;
			} else {
				console.log('Unknown code, expected %s got %s', code, req.body.code);
				res.status(400).end();
				return;
			}
		} else if (req.body.grant_type == 'refresh_token') {
			nosql.all(function(token) {
				return (token.refresh_token == req.body.refresh_token);
			}, function(err, tokens) {
				if (tokens.length == 1) {
					console.log("We found a matching token: %s", req.body.refresh_token);
					var access_token = randomstring.generate();
					var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token };
					nosql.insert({ access_token: access_token, client_id: req.body.client_id });
					console.log('Issuing access token %s for refresh token %s', access_token, req.body.refresh_token);
					res.status(200).json(token_response);
					return;
				} else {
					console.log('No matching token was found.');
					res.status(401).end();
				}
			});
		} else {
			console.log('Unknown grant type %s', req.body.grant_type);
			res.status(400).end();
		}
	} else {
		console.log('Unknown client or secret, expected %s got %s', client.client_id, req.body.client_id);
		res.status(400).end();
		return;
	}
});

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
