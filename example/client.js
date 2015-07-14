var express = require("express");
var request = require("request");
var url = require("url");

var app = express();


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

app.use('/', express.static('files'));

app.get('/authorize', function(req, res){
	
	app.state = 'foo';
	
	var authorizeUrl = url.parse(authServer.authorizationEndpoint, true);
	delete authorizeUrl.search; // this is to get around odd behavior in the node URL library
	authorizeUrl.query.response_type = 'code';
	authorizeUrl.query.scope = client.scope;
	authorizeUrl.query.client_id = client.client_id;
	authorizeUrl.query.redirect_uri = client.redirect_uri
	authorizeUrl.query.state = app.state;
	
	console.log("redirect", url.format(authorizeUrl));
	res.redirect(url.format(authorizeUrl));
});


app.get("/oauth/callback", function(req, res){
	var state = req.query.state;
	if (state == app.state) {
		console.log('State value matches: expected %s got %s', app.state, state);
	} else {
		console.log('State DOES NOT MATCH: expected %s got %s', app.state, state);
	}

	var code = req.query.code;
	console.log("code %s",code);

	var requestOptions = {
		url : authServer.tokenEndpoint,
		method: 'POST',
		json: true,
		form: {
			grant_type: 'authorization_code',
			code: code,
			client_id: client.client_id,
			client_secret: client.client_secret,
			redirect_uri: client.redirect_uri
		}

	};

	request(requestOptions, function(error, authorizationServerResponse, body) {
		if (error) {
			console.log("error while retrieving access token");
			res.status(500).end();
			return;
		}

		if (authorizationServerResponse.statusCode !== 200) {
			console.log("error while retrieving access token with status code %s %j", authorizationServerResponse.statusCode, body);
			res.status(500).end();
			return;
		}
		console.log("acces token", body.access_token);
		res.status(200).end();
	});

});

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
