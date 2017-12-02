// for authorizationServer.js

var clients = [
	{
		client_id: "oauth-client-1",
		client_secret: "oauth-client-secret-1",
		redirect_uris: ["http://localhost:9000/callback"],
		scope: "foo bar"
	}
];



// for client.js

var client = {
	client_id: "oauth-client-1",
	client_secret: "oauth-client-secret-1",
	redirect_uris: ["http://localhost:9000/callback"],
	scope: "foo bar"
};

var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

