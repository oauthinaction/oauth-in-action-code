// protectedResource.js

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
			out.sub = user.sub;
		} else if (scope == 'email') {
			__.each(['email', 'email_verified'], function(claim) {
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

// client.js

app.get('/userinfo', function(req, res) {
	
	var headers = {
		'Authorization': 'Bearer ' + access_token
	};
	
	var resource = request('GET', authServer.userInfoEndpoint,
		{headers: headers}
	);
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		console.log('Got data: ', body);
	
		userInfo = body;
	
		res.render('userinfo', {userInfo: userInfo, id_token: id_token});
		return;
	} else {
		res.render('error', {error: 'Unable to fetch user information'});
		return;
	}
	
});
