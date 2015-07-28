var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.use('/', express.static('files'));

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

app.post("/resource", function(req, res){

	// check the auth header first
	var auth = req.headers['authorization'];
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	}
	if (!inToken) {
		// not in the header, check in the form body
		if (req.body && req.body.access_token) {
			inToken = req.body.access_token;
		}
	}
	if (!inToken) {
		// not in the header or body, check the parameter
		var url_parts = url.parse(req.url, true);
		if (url_parts.query && url_parts.query.access_token) {
			inToken = url_parts.query.access_token
		}
	}
	
	console.log('Incoming token: %s', inToken);
	
	nosql.all(function(token) {
		return (token.access_token == inToken);
	}, function(err, tokens) {
		if (tokens.length == 1) {
			console.log("We found a matching token: %s", inToken);
			res.json(resource);
		} else {
			console.log('No matching token was found.');
			res.status(401).end();
		}
	});
	
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
