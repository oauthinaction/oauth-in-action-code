var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var qs = require("qs");
var querystring = require('querystring');
var request = require("sync-request");
var __ = require('underscore');
var base64url = require('base64url');
var jose = require('jsrsasign');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

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
	nosql.one(function(token) {
		if (token.access_token == inToken) {
			return token;	
		}
	}, function(err, token) {
		if (token) {
			console.log("We found a matching token: %s", inToken);
		} else {
			console.log('No matching token was found.');
		}
		req.access_token = token;
		next();
		return;
	});
	
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};

app.options('/resource', cors());

app.post("/resource", cors(), getAccessToken, function(req, res){
	console.log(req.access_token);
	if (req.access_token) {
		res.json(resource);
	} else {
		res.status(401).end();
	}
	
});

var userInfoEndpoint = function(req, res) {
	
	if (!__.contains(req.access_token.scope, 'openid')) {
		res.status(403).end();
		return;
	}
	
	var user = req.access_token.user;
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


var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
