var express = require("express");
var path = require("path");

var app = express();

app.set('view engine', 'html');
app.set('views', 'files/clientImplicitGrant');

app.use('/', express.static('files/clientImplicitGrant'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});

app.get("/*", function(req, res){
	res.sendFile(path.join(__dirname, "files/clientImplicitGrant/callback.html"));
});