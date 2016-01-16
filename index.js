var OAuth2Provider = function(service){
	this.service = service;
};

OAuth2Provider.create = function(service){
	return new OAuth2Provider(service);
};

// In seconds
OAuth2Provider.AUTH_CODE_TTL = 10;
OAuth2Provider.DEVICE_CODE_TTL = 10;
OAuth2Provider.ACCESS_TOKEN_TTL = 5;
OAuth2Provider.REFRESH_TOKEN_TTL = 300;

// In milliseconds
OAuth2Provider.POLL_INTERVAL = 6000;

var Params = {
	RESPONSE_TYPE: 'response_type',
	CLIENT_ID: 'client_id',
	CLIENT_SECRET: 'client_secret',
	REDIRECT_URI: 'redirect_uri',
	SCOPE: 'scope',
	ALLOW: 'allow',
	STATE: 'state',
	DEVICE_ID: 'device_id',
	CODE: 'code',
	GRANT_TYPE: 'grant_type',
	USERNAME: 'username',
	PASSWORD: 'password',
	REFRESH_TOKEN: 'refresh_token'
};

var GrantType = OAuth2Provider.GRANT_TYPE = {
	AUTHORIZATION_CODE: 1,
	CLIENT_CREDENTIALS: 2,
	PASSWORD_IMPLICIT: 4,
	PASSWORD_SECURE: 8,
	LIMITED_DEVICE: 16
};

var GrantTypes = {
	AUTHORIZATION_CODE: 'authorization_code',
	CLIENT_CREDENTIALS: 'client_credentials',
	PASSWORD: 'password',
	REFRESH_TOKEN: 'refresh_token',
	LIMITED_DEVICE: 'limited_device'
};

var Status = OAuth2Provider.STATUS = {
	MULTIPLE: function(p){
		return {
			error: 'invalid_request',
			error_description: 'OAuth 2 parameters can only have a single value: '+p
		};
	},
	MISSING: function(p){
		return {
			error: 'invalid_request',
			error_description: 'Required parameter is missing: '+p
		};
	},
	ACCESS_DENIED: {
		error: 'access_denied',
		error_description: 'User has denied authorization for the current app!'
	},
	INVALID_CLIENT_ID: {
		error: 'invalid_client',
		error_description: 'The OAuth client was not found!'
	},
	INVALID_CLIENT_SECRET: {
		error: 'invalid_client',
		error_description: 'Client secret does not match!'
	},
	REDIRECT_URI_MISMATCH: function(uri){
		return {
			error: 'redirect_uri_mismatch',
			error_description: 'The redirect URI in the request: '+uri+' did not match a registered redirect URI!'
		};
	},
	INVALID_SCOPE: function(scopes){
		return {
			error: 'invalid_scope',
			error_description: 'Invalid scopes: ['+scopes+']'
		}
	},
	UNSUPPORTED_RESPONSE_TYPE: {
		error: 'unsupported_response_type',
		error_description: 'Unsupported response type!'
	},
	DEVICE_NOT_FOUND: {
		error: 'device_not_found',
		error_description: 'Device not found!'
	},
	UNSUPPORTED_GRANT_TYPE: {
		error: 'unsupported_grant_type',
		error_description: 'Unsupported grant type!'
	},
	INVALID_GRANT: {
		error: 'invalid_grant',
		error_description: 'Bad Request'
	},
	TOKEN_NOT_FOUND: {
		error: 'token_not_found'
	},
	TOKEN_EXPIRED: {
		error: 'token_expired'
	}
};

var ResponseType = {
	CODE: 'code',
	TOKEN: 'token',
	DEVICE_CODE: 'device_code'
};

/**
 * Extracts a param value from params map. Returns false when multiple values.
 */
OAuth2Provider.$getParam = function(params, param){
	var value = params[param];
	return value instanceof Array ? (value.length > 1 ? false : value[0]) : value;
};

OAuth2Provider.prototype.$tokenCodeCommon = function(params, client, cb){
	var redirect_uri = OAuth2Provider.$getParam(params, Params.REDIRECT_URI);

	if(redirect_uri === false){
		return cb(null, 400, Status.MULTIPLE(Params.REDIRECT_URI));
	}
	
	if(!redirect_uri){
		return cb(null, 400, Status.MISSING(Params.REDIRECT_URI));
	}

	if(client.redirectURIs.indexOf(redirect_uri) < 0){
		return cb(null, 400, Status.REDIRECT_URI_MISMATCH(redirect_uri));
	}

	var state = OAuth2Provider.$getParam(params, Params.STATE);

	if(state === false){
		return cb(null, 400, Status.MULTIPLE(Params.STATE));
	}

	var allow = OAuth2Provider.$getParam(params, Params.ALLOW);

	if(allow === false){
		var e = Status.MULTIPLE(Params.ALLOW);
		e.state = state;
		return cb(null, 400, e);
	}

	if(!allow){
		var e = Status.MISSING(Params.ALLOW);
		e.state = state;
		return cb(null, 400, e);
	}	

	if(!(allow === 'ok' || allow === '1' || allow === 'true')){
		var e = Status.ACCESS_DENIED;
		e.state = state;
		return cb(null, 401, e);
	}

	cb(null, 200, {
		state: state,
		redirect_uri: redirect_uri
	});
};
	
OAuth2Provider.prototype.$code = function(params, client, user_id, scopes, cb){
	var service = this.service;

	this.$tokenCodeCommon(params, client, function(error, status, data){
		if(error) return cb(error, 500);
		if(status !== 200) return cb(null, status, data);

		var client_secret = OAuth2Provider.$getParam(params, Params.CLIENT_SECRET);
		
		if(client_secret === false){
			var e = Status.MULTIPLE(Params.CLIENT_SECRET);
			e.state = data.state;
			return cb(null, 400, e);
		}

		if(!client_secret){
			var e = Status.MISSING(Params.CLIENT_SECRET);
			e.state = data.state;
			return cb(null, 400, e);
		}

		if(client.secret !== client_secret){
			var e = Status.INVALID_CLIENT_SECRET;
			e.state = data.state;
			return cb(null, 401, e);
		}

		service.removeAuthCode(client.id, user_id, function(error){
			if(error) return cb(error, 500);

			service.generateAuthCode(function(error, code){
				if(error) return cb(error, 500);

				service.saveAuthCode({
					code: code,
					clientId: client.id,
					userId: user_id,
					scopes: scopes,
					redirectURI: data.redirect_uri,
					timestamp: +new Date
				}, function(error){
					if(error) return cb(error, 500);

					cb(null, 200, {
						code: code,
						state: data.state,
						redirect_uri: data.redirect_uri,
						expires_in: OAuth2Provider.AUTH_CODE_TTL
					});
				});
			});
		});
	});	
};

OAuth2Provider.prototype.$token = function(params, client, user_id, scopes, cb){
	var $this = this;
	var service = this.service;

	this.$tokenCodeCommon(params, client, function(error, status, data){
		if(error) return cb(error, 500);
		if(status !== 200) return cb(null, status, data);

		var device_id = OAuth2Provider.$getParam(params, Params.DEVICE_ID);

		if(device_id === false){
			var e = Status.MULTIPLE(Params.DEVICE_ID);
			e.state = data.state;
			return cb(null, 400, e);
		}

		if(!device_id){
			var e = Status.MISSING(Params.DEVICE_ID);
			e.state = data.state;
			return cb(null, 400, e);
		}

		service.getDevice(device_id, function(error, device){
			if(error) return cb(error, 500);

			if(!device) {
				var e = Status.DEVICE_NOT_FOUND;
				e.state = data.state;
				return cb(null, 404, e);
			}

			$this.$saveAccessToken(client.id, user_id, device_id, scopes, cb);
		});
	});
};
	
OAuth2Provider.prototype.$deviceCode = function(params, client, scopes, cb){
	var device_id = OAuth2Provider.$getParam(params, Params.DEVICE_ID);

	if(device_id === false){
		return cb(null, 400, Status.MULTIPLE(Params.DEVICE_ID));
	}

	if(!device_id){
		return cb(null, 400, Status.MISSING(Params.DEVICE_ID));
	}

	var service = this.service;

	service.removeDeviceCode(client.id, device_id, function(error){
		if(error) return cb(error, 500);

		service.generateDeviceCode(function(error, code){
			if(error) return cb(error, 500);

			service.saveDeviceCode({
				code: code,
				clientId: client.id,
				userId: null,
				deviceId: device_id,
				scopes: scopes,
				timestamp: +new Date
			}, function(error){
				if(error) return cb(error, 500);

				cb(null, 200, {
					code: code,
					poll_interval: OAuth2Provider.POLL_INTERVAL,
					expires_in: OAuth2Provider.DEVICE_CODE_TTL
				});
			});
		});
	});
};

/**
 * Authorization code generation
 */
OAuth2Provider.prototype.authorization = function(params, user_id, cb){
	var response_type = OAuth2Provider.$getParam(params, Params.RESPONSE_TYPE);

	if(response_type === false){
		return cb(null, 400, Status.MULTIPLE(Params.RESPONSE_TYPE));
	}

	if(!response_type){
		return cb(null, 400, Status.MISSING(Params.RESPONSE_TYPE));
	}

	var client_id = OAuth2Provider.$getParam(params, Params.CLIENT_ID);
	
	if(client_id === false){
		return cb(null, 400, Status.MULTIPLE(Params.CLIENT_ID));
	}

	if(!client_id){
		return cb(null, 400, Status.MISSING(Params.CLIENT_ID));
	}

	var scope = OAuth2Provider.$getParam(params, Params.SCOPE);

	if(scope === false){
		return cb(null, 400, Status.MULTIPLE(Params.SCOPE));
	}

	if(!scope){
		return cb(null, 400, Status.MISSING(Params.SCOPE));
	}

	var scopes = scope.split(',');

	if(!scopes.length){
		return cb(null, 400, Status.MISSING(Params.SCOPE));
	}

	var $this = this;

	this.service.getClient(client_id, function(error, client){
		if(error) return cb(error, 500);

		if(!client) {
			return cb(null, 401, Status.INVALID_CLIENT_ID);
		}

		var cscopes = client.scopes;

		var not_allowed = scopes.filter(function(scope){
			return cscopes.indexOf(scope) < 0;
		});

		if(not_allowed.length){
			return cb(null, 400, Status.INVALID_SCOPE(not_allowed));
		}

		switch(response_type){
			case ResponseType.CODE: return $this.$code(params, client, user_id, scopes, cb);
			case ResponseType.TOKEN: return $this.$token(params, client, user_id, scopes, cb);
			case ResponseType.DEVICE_CODE: return $this.$deviceCode(params, client, scopes, cb);
			default: return cb(null, 400, Status.UNSUPPORTED_RESPONSE_TYPE);
		}
	});

};

OAuth2Provider.prototype.$authorizationCode = function(params, client, cb){
	if(client.grantType !== GrantType.AUTHORIZATION_CODE){
		return cb(null, 400, Status.INVALID_GRANT);
	}

	var client_secret = OAuth2Provider.$getParam(params, Params.CLIENT_SECRET);

	if(client_secret === false){
		return cb(null, 400, Status.MULTIPLE(Params.CLIENT_SECRET));
	}

	if(!client_secret){
		return cb(null, 400, Status.MISSING(Params.CLIENT_SECRET));
	}

	if(client.secret !== client_secret){
		return cb(null, 401, Status.INVALID_CLIENT_SECRET);
	}

	var redirect_uri = OAuth2Provider.$getParam(params, Params.REDIRECT_URI);

	if(redirect_uri === false){
		return cb(null, 400, Status.MULTIPLE(Params.REDIRECT_URI));
	}

	if(!redirect_uri){
		return cb(null, 400, Status.MISSING(Params.REDIRECT_URI));
	}

	var code = OAuth2Provider.$getParam(params, Params.CODE);

	if(code === false){
		return cb(null, 400, Status.MULTIPLE(Params.CODE));
	}

	if(!code){
		return cb(null, 400, Status.MISSING(Params.CODE));
	}

	var $this = this;
	var service = this.service;

	service.getAuthCode(code, function(error, ac){
		if(error) return cb(error, 500);
		if(!ac) return cb(null, 400, Status.INVALID_GRANT);

		if(client.id !== ac.clientId){
			return cb(null, 401, Status.INVALID_CLIENT_ID);
		}

		if(ac.redirectURI !== redirect_uri){
			return cb(null, 400, Status.REDIRECT_URI_MISMATCH(redirect_uri));
		}

		service.removeAuthCodeFromId(ac.code, function(error){
			if(error) return cb(error, 500);
			$this.$saveAccessToken(client.id, ac.userId, null, ac.scopes, cb);
		});
	});
};

OAuth2Provider.prototype.$clientCredentials = function(params, client, cb){
	if(client.grantType !== GrantType.CLIENT_CREDENTIALS){
		return cb(null, 400, Status.INVALID_GRANT);
	}

	var client_secret = OAuth2Provider.$getParam(params, Params.CLIENT_SECRET);

	if(client_secret === false){
		return cb(null, 400, Status.MULTIPLE(Params.CLIENT_SECRET));
	}

	if(!client_secret){
		return cb(null, 400, Status.MISSING(Params.CLIENT_SECRET));
	}

	if(client.secret !== client_secret){
		return cb(null, 401, Status.INVALID_CLIENT_SECRET);
	}

	var scope = OAuth2Provider.$getParam(params, Params.SCOPE);

	if(scope === false){
		return cb(null, 400, Status.MULTIPLE(Params.SCOPE));
	}

	if(!scope){
		return cb(null, 400, Status.MISSING(Params.SCOPE));
	}

	var scopes = scope.split(',');

	if(!scopes.length){
		return cb(null, 400, Status.MISSING(Params.SCOPE));
	}

	var cscopes = client.scopes;
	
	var not_allowed = scopes.filter(function(scope){
		return cscopes.indexOf(scope) < 0;
	});

	if(not_allowed.length){
		return cb(null, 400, Status.INVALID_SCOPE(not_allowed));
	}

	this.$saveAccessToken(client.id, null, null, scopes, cb);
};

/**
 * First party clients or secure clients
 */
OAuth2Provider.prototype.$password = function(params, client, cb){
	if(!(client.grantType === GrantType.PASSWORD_IMPLICIT || 
		client.grantType === GrantType.PASSWORD_SECURE)){
		return cb(null, 400, Status.INVALID_GRANT);
	}

	var username = OAuth2Provider.$getParam(params, Params.USERNAME);

	if(username === false){
		return cb(null, 400, Status.MULTIPLE(Params.USERNAME));
	}

	if(!username){
		return cb(null, 400, Status.MISSING(Params.USERNAME));
	}
	
	var password = OAuth2Provider.$getParam(params, Params.PASSWORD);
	
	if(password === false){
		return cb(null, 400, Status.MULTIPLE(Params.PASSWORD));
	}
	
	if(!password){
		return cb(null, 400, Status.MISSING(Params.PASSWORD));
	}

	var scope = OAuth2Provider.$getParam(params, Params.SCOPE);

	if(scope === false){
		return cb(null, 400, Status.MULTIPLE(Params.SCOPE));
	}

	if(!scope){
		return cb(null, 400, Status.MISSING(Params.SCOPE));
	}

	var scopes = scope.split(',');

	if(!scopes.length){
		return cb(null, 400, Status.MISSING(Params.SCOPE));
	}

	var cscopes = client.scopes;
	
	var not_allowed = scopes.filter(function(scope){
		return cscopes.indexOf(scope) < 0;
	});

	if(not_allowed.length){
		return cb(null, 400, Status.INVALID_SCOPE(not_allowed));
	}

	var $this = this;
	var service = this.service;
		
	if(client.grantType === GrantType.PASSWORD_IMPLICIT){

		var device_id = OAuth2Provider.$getParam(params, Params.DEVICE_ID);

		if(device_id === false){
			return cb(null, 400, Status.MULTIPLE(Params.DEVICE_ID));
		}

		if(!device_id){
			return cb(null, 400, Status.MISSING(Params.DEVICE_ID));
		}

		return service.getDevice(device_id, function(error, device){
			if(error) return cb(error, 500);

			if(!device) {
				return cb(null, 404, Status.DEVICE_NOT_FOUND);
			}

			service.authenticate(username, password, function(error, ok, data){
				if(error) return cb(error, 500);
				if(!ok) return cb(null, 401, data);

				if(!data.user_id) return cb(new Error('Missing user_id parameter related to username!'));

				$this.$saveAccessToken(client.id, data.user_id, device_id, scopes, cb);
			});
		});

	}

	var client_secret = OAuth2Provider.$getParam(params, Params.CLIENT_SECRET);

	if(client_secret === false){
		return cb(null, 400, Status.MULTIPLE(Params.CLIENT_SECRET));
	}

	if(!client_secret){
		return cb(null, 400, Status.MISSING(Params.CLIENT_SECRET));
	}

	if(client.secret !== client_secret){
		return cb(null, 401, Status.INVALID_CLIENT_SECRET);
	}

	service.authenticate(username, password, function(error, ok, data){
		if(error) return cb(error, 500);
		if(!ok) return cb(null, 401, data);

		if(!data.user_id) return cb(new Error('Missing user_id parameter related to username!'));

		$this.$saveAccessToken(client.id, data.user_id, null, scopes, cb);
	});
};

OAuth2Provider.prototype.$refreshToken = function(params, client, cb){
	var refresh_token = OAuth2Provider.$getParam(params, Params.REFRESH_TOKEN);
		
	if(refresh_token === false){
		return cb(null, 400, Status.MULTIPLE(Params.REFRESH_TOKEN));
	}
		
	if(!refresh_token){
		return cb(null, 400, Status.MISSING(Params.REFRESH_TOKEN));
	}

	if(client.grantType === GrantType.CLIENT_CREDENTIALS || client.grantType === GrantType.PASSWORD_SECURE){

		var client_secret = OAuth2Provider.$getParam(params, Params.CLIENT_SECRET);

		if(client_secret === false){
			return cb(null, 400, Status.MULTIPLE(Params.CLIENT_SECRET));
		}

		if(!client_secret){
			return cb(null, 400, Status.MISSING(Params.CLIENT_SECRET));
		}

		if(client.secret !== client_secret){
			return cb(null, 401, Status.INVALID_CLIENT_SECRET);
		}
	}

	var $this = this;
	var service = this.service;

	service.getAccessTokenFromRT(refresh_token, function(error, token){
		if(error) return cb(error, 500);
		if(!token) return cb(null, 400, Status.INVALID_GRANT);

		// Save a new ACCESS_TOKEN before remove the old one...
		$this.$saveAccessToken(token.clientId, token.userId, token.deviceId, token.scopes,
		function(error, status, data){
			if(error) return cb(error, 500);

			service.removeAccessTokenFromId(token.access_token, function(error){
				if(error) return cb(error, 500);
				cb(null, 200, data);
			}); 
		});
	});
};

OAuth2Provider.prototype.$limitedDevice = function(params, client, cb){
	if(client.grantType !== GrantType.LIMITED_DEVICE){
		return cb(null, 400, Status.INVALID_GRANT);
	}

	var code = OAuth2Provider.$getParam(params, Params.CODE);

	if(code === false){
		return cb(null, 400, Status.MULTIPLE(Params.CODE));
	}

	if(!code){
		return cb(null, 400, Status.MISSING(Params.CODE));
	}

	var $this = this;
	var service = this.service;
			
	service.getDeviceCode(code, function(error, dc){
		if(error) return cb(error, 500);
		if(!dc) return cb(null, 400, Status.INVALID_GRANT);

		// Is device confirmed???

		$this.$saveAccessToken(client.id, dc.userId, dc.deviceId, dc.scopes, 
			function(error, status, data){
				if(error) return cb(error, 500);
				if(status !== 200) return cb(null, status, data);

				service.removeDeviceCodeFromId(code, function(error){
					if(error) return cb(error, 500);
					cb(null, 200, data);
				});
			});
	});
};
	
OAuth2Provider.prototype.grant = function(params, cb){
	var grant_type = OAuth2Provider.$getParam(params, Params.GRANT_TYPE);

	if(grant_type === false){
		return cb(null, 400, Status.MULTIPLE(Params.GRANT_TYPE));
	}

	if(!grant_type){
		return cb(null, 400, Status.MISSING(Params.GRANT_TYPE));
	}

	var client_id = OAuth2Provider.$getParam(params, Params.CLIENT_ID);

	if(client_id === false){
		return cb(null, 400, Status.MULTIPLE(Params.CLIENT_ID));
	}

	if(!client_id){
		return cb(null, 400, Status.MISSING(Params.CLIENT_ID));
	}

	var $this = this;
	var service = this.service;

	service.getClient(client_id, function(error, client){
		if(error) return cb(error, 500);
		if(!client) return cb(null, 401, Status.INVALID_CLIENT_ID);

		switch(grant_type){
			case GrantTypes.AUTHORIZATION_CODE: return $this.$authorizationCode(params, client, cb);
			case GrantTypes.CLIENT_CREDENTIALS: return $this.$clientCredentials(params, client, cb);
			case GrantTypes.PASSWORD: return $this.$password(params, client, cb);
			case GrantTypes.REFRESH_TOKEN: return $this.$refreshToken(params, client, cb);
			case GrantTypes.LIMITED_DEVICE: return $this.$limitedDevice(params, client, cb);
			default: return cb(null, 400, Status.UNSUPPORTED_GRANT_TYPE);
		}
	});
};

OAuth2Provider.prototype.$saveAccessToken = function(client_id, user_id, device_id, scopes, cb){
	var service = this.service;

	service.removeAccessToken(client_id, user_id, device_id, function(error){
		if(error) return cb(error, 500);

		service.generateTokens(function(error, at, rt){
			if(error) return cb(error, 500);

			var token = {
				accessToken: at,
				refreshToken: rt,
				timestamp: +new Date,
				scopes: scopes,
				clientId: client_id
			};

			if(user_id){
				token.userId = user_id;
			}

			if(device_id){
				token.deviceId = device_id;
			}

			service.saveAccessToken(token, function(error){
				if(error) return cb(error, 500);

				cb(null, 200, {
					access_token: at,
					refresh_token: rt,
					at_expires_in: OAuth2Provider.ACCESS_TOKEN_TTL,
					rt_expires_in: OAuth2Provider.REFRESH_TOKEN_TTL
				});
			});
		});
	});
};

/**
 * Gets token info
 */
OAuth2Provider.prototype.tokenInfo = function(access_token, cb){
	this.service.getAccessTokenFromId(access_token, function(error, token){
		if(error) return cb(error, 500);
		if(!token) return cb(null, null);

		var expires_in = OAuth2Provider.ACCESS_TOKEN_TTL*1000 - 
			(+new Date - token.timestamp);

		// AccessToken and RefreshToken expirations!!!
		var info = {
			client_id: token.clientId,
			scopes: token.scopes,
			expires_in: expires_in < 0 ? 0 : expires_in
		};

		if(token.userId){
			info.user_id = token.userId;
		}

		if(token.deviceId){
			info.device_id = token.deviceId;
		}

		cb(null, info);
	});
};

OAuth2Provider.prototype.canAccess = function(access_token, scope, cb){
	this.service.getAccessTokenFromId(access_token, function(error, token){
		if(error) return cb(error, 500);
		if(!token) return cb(null, 403, Status.TOKEN_NOT_FOUND);

		// Has expired?
		if(+new Date - token.timestamp >= OAuth2Provider.ACCESS_TOKEN_TTL){
			return cb(null, 403, Status.TOKEN_EXPIRED);
		}

		if(token.scopes.indexOf(scope) < 0){
			return cb(null, 403);
		}

		cb(null, 200);
	});
};

OAuth2Provider.prototype.revokeToken = function(access_token, cb){
	var service = this.service;

	service.getAccessTokenFromId(access_token, function(error, token){
		if(error) return cb(error, 500);
		if(!token) return cb(null, 404, Status.TOKEN_NOT_FOUND);

		service.removeAccessTokenFromId(access_token, function(error){
			if(error) return cb(error, 500);
			cb(null, 200);
		});
	});
};

OAuth2Provider.prototype.confirmDevice = function(code, user_id, cb){
	this.service.confirmDeviceCode(code, user_id, function(error, ok){
		if(error) return cb(error, false);
		cb(null, ok);
	});
};

module.exports = OAuth2Provider;
