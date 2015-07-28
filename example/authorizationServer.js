var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var nosql = require('nosql').load('database.nosql');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/oauth/authorize',
	tokenEndpoint: 'http://localhost:9001/oauth/token'
};

// client information
var client = {
	client_id: '788732372078-l4duigdj7793hb53871p3frd05v7n6df',
	client_secret: '',
	scope: '',
	redirect_uri: 'http://localhost:9000/oauth/callback'
};

var code = null;

app.use('/', express.static('files'));

app.get("/oauth/authorize", function(req, res){
	
	if (req.query.client_id == client.client_id) {
		code = randomstring.generate(8);

		var urlParsed =url.parse(req.query.redirect_uri);
		delete urlParsed.search; // this is a weird behavior of the URL library
		urlParsed.query = urlParsed.query || {};
		urlParsed.query.code = code;
		urlParsed.query.state = req.query.state; 

		res.redirect(url.format(urlParsed));
		
	} else {
		console.log('Unknown client, expected %s got %s', client.client_id, res.query.client_id);
	}

});


app.post("/oauth/token", function(req, res){
	
	if (req.body.client_id == client.client_id && req.body.client_secret == client.client_secret) {
		if (req.body.code == code) {
			code = null; // burn our code, it's been used
			var token = { access_token: randomstring.generate(), token_type: 'Bearer' };
			nosql.insert(token);
			res.status(200).json(token);
		} else {
			console.log('Unknown code, expected %s got %s', code, req.body.code);
			res.status(400).end();
		}
	} else {
		console.log('Unknown client or secret, expected %s got %s', client.client_id, req.body.client_id);
		res.status(400).end();
	}
});

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
