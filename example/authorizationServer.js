var express = require("express");
var url = require("url");

var app = express();

app.get("/oauth/authorize", function(req, res){

	var code = "SplxlOBeZQQYbYS6WxSbIA";

	var urlParsed =url.parse(req.query.redirect_uri);

	urlParsed.query = urlParsed.query || {};
	urlParsed.query.code = code;
	urlParsed.query.state = req.query.state; 

	res.redirect(url.format(urlParsed));
});


app.post("/oauth/token", function(req, res){
	res.status(200).json({ access_token: '2YotnFZFEjr1zCsicMWpAA' });
});

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
