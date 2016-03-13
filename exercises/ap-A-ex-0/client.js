var express = require("express");
var cons = require('consolidate');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

var access_token = null;
var refresh_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
