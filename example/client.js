var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var cons = require('consolidate');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files');

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

	var form_data = qs.stringify({
				grant_type: 'authorization_code',
				code: code,
				client_id: client.client_id,
				client_secret: client.client_secret,
				redirect_uri: client.redirect_uri
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	console.log("form: %s", form_data);

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);
	var body = JSON.parse(tokRes.getBody());
	console.log("acces token", body.access_token);

	res.render('access_token', {access_token: body.access_token});

});

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
