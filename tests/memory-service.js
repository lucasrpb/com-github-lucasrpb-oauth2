var crypto = require('crypto');
var OAuth2Provider = require('../index');

var GrantType = OAuth2Provider.GRANT_TYPE;

/**
 * Simulates a provider implementation
 * @constructor
 */
var OAuth2Service = function(){

	this.clients = {
		'1': {
			id: '1',
			secret: '123',
			redirectURIs: ['http://localhost:9000'],
			scopes: ['profile', 'photos'],
			grantType: GrantType.AUTHORIZATION_CODE
		}
	};

	this.devices = {
		'1': {
			id: '1'
		}
	};	

	this.authCodes = {};
	this.deviceCodes = {};

	this.accessTokens = {};

};

OAuth2Service.prototype.getClient = function(id, cb){
	cb(null, this.clients[id]);
};

OAuth2Service.prototype.removeAuthCodeFromId = function(code, cb){
	this.authCodes[code] = undefined;
	cb(null);
};

OAuth2Service.prototype.removeAuthCode = function(client_id, user_id, cb){
	for(var code in this.authCodes){
		if(this.authCodes.hasOwnProperty(code)){

			var ac = this.authCodes[code];

			if(ac.clientId === client_id && ac.userId === user_id){
				this.authCodes[code] = undefined;
				break;
			}
		}
	}

	cb(null);
};

OAuth2Service.prototype.removeDeviceCode = function(client_id, device_id, cb){
	for(var code in this.deviceCodes){
		if(this.deviceCodes.hasOwnProperty(code)){

			var dc = this.deviceCodes[code];

			if(dc.clientId === client_id && dc.deviceId === device_id){
				this.deviceCodes[code] = undefined;
				break;
			}
		}
	}

	cb(null);
};	

OAuth2Service.prototype.generateAuthCode = function(cb){
	crypto.randomBytes(20, function(error, buf) {
	  if (error) return cb(error);
	  cb(null, buf.toString('hex'));
	});
};

OAuth2Service.prototype.saveAuthCode = function(ac, cb) {
	this.authCodes[ac.code] = ac;
	cb(null);
};

OAuth2Service.prototype.removeAccessToken = function(client_id, user_id, device_id, cb){
	for(var code in this.accessTokens){
		if(this.accessTokens.hasOwnProperty(code)){

			var at = this.accessTokens[code];

			if(at.clientId === client_id && (!user_id || at.userId === user_id) && 
				(!device_id || at.deviceId === deviceId)){
				this.accessTokens[code] = undefined;
				break;
			}
		}
	}
	
	cb(null);
};

OAuth2Service.prototype.removeAccessTokenFromId = function(token, cb){
	this.accessTokens[token] = undefined;
	cb(null);
};

OAuth2Service.prototype.saveAccessToken = function(at, cb){
	this.accessTokens[at.accessToken] = at;
	cb(null);
};

OAuth2Service.prototype.generateTokens = function(cb){
	crypto.randomBytes(20, function(error, at) {
	  if (error) return cb(error);
	  
	  crypto.randomBytes(20, function(error, rt) {
		if (error) return cb(error);
		  cb(null, at.toString('hex'), rt.toString('hex'));
		});
	});
};

OAuth2Service.prototype.getDevice = function(id, cb){
	cb(null, this.devices[id]);
};

OAuth2Service.prototype.getAuthCode = function(code, cb){
	cb(null, this.authCodes[code]);
};

OAuth2Service.prototype.authenticate = function(user_id, password, cb){
	if(user_id === 'lucasrpb' && password === '1234')
		return cb(null, true, { user_id: 1 });

	cb(null, false, {error: 'invalid_auth'})
};

OAuth2Service.prototype.getAccessTokenFromRT = function(rt, cb){
	for(var code in this.accessTokens){
		if(this.accessTokens.hasOwnProperty(code)){

			var at = this.accessTokens[code];

			if(at.refreshToken === rt){
				return cb(null, at);
			}
		}
	}
	
	cb(null, null);
};

OAuth2Service.prototype.getAccessTokenFromId = function(token, cb){
	cb(null, this.accessTokens[token]);
};

OAuth2Service.prototype.generateDeviceCode = function(cb){
	crypto.randomBytes(10, function(error, buf) {
	  if (error) return cb(error);
	  cb(null, buf.toString('hex'));
	});
};

OAuth2Service.prototype.saveDeviceCode = function(dc, cb) {
	this.deviceCodes[dc.code] = dc;
	cb(null);
};

OAuth2Service.prototype.getDeviceCode = function(code, cb){
	cb(null, this.deviceCodes[code]);
};

OAuth2Service.prototype.confirmDeviceCode = function(code, user_id, cb){
	var dc = this.deviceCodes[code];

	if(dc){
		dc.userId = user_id;
	}

	cb(null, true);
};

OAuth2Service.prototype.removeDeviceCodeFromId = function(code, cb){
	this.deviceCodes[code] = undefined;
	cb(null);
};

module.exports = new OAuth2Service;