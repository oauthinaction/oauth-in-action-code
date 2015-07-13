var express = require("express");
var request = require("request");
var url = require("url");

var app = express();

app.get("/authorize", function(req, res){
	var authorizeUrl = url.format({
		protocol: 'https', 
		host: 'accounts.google.com',
		pathname: '/o/oauth2/auth', 
		query: {
			response_type: 'code', 
			scope: 'openid', 
			client_id: '788732372078-l4duigdj7793hb53871p3frd05v7n6df.apps.googleusercontent.com',
			redirect_uri: 'http://localhost:8080/oauth/google/callback',
			//TODO state
			state: ''
		}
	});

	res.redirect(authorizeUrl);
});


app.get("/oauth/google/callback", function(req, res){
	//TODO state
	var state = req.query.state;

	var code = req.query.code;
	console.log("code %s",code);

	var requestOptions = {
		url : 'https://accounts.google.com/o/oauth2/token',
		method: 'POST',
		json: true,
		form: {
			grant_type: 'authorization_code',
			code: code,
			client_id: '788732372078-l4duigdj7793hb53871p3frd05v7n6df.apps.googleusercontent.com',
			client_secret:'',
			redirect_uri: 'http://localhost:8080/oauth/google/callback'
		}

	};

	request(requestOptions, function(error, googleResponse, body) {
		if (error) {
			console.log("error while retrieving access token");
			res.status(500).end();
			return;
		}

		if (googleResponse.statusCode !== 200) {
			console.log("error while retrieving access token with status code %s %j", googleResponse.statusCode, body);
			res.status(500).end();
			return;
		}
		console.log("acces token", body.access_token);
		res.status(200).end();
	});

});

var server = app.listen(8080, function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('Example app listening at http://%s:%s', host, port);
});
 
