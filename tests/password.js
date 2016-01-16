/**
 * Password Authorization
 * @type {OAuth2Provider|exports|module.exports}
 */
var OAuth2Provider = require('../index');
var Service = require('./memory-service');

var Provider = OAuth2Provider.create(Service);

Provider.grant({
	grant_type: 'password',
	username: 'lucasrpb',
	password: '1234',
	client_id: '1',
	client_secret: '123',
	scope: 'photos,profile',
	device_id: '1'
}, function(error, status, data){
	
	if(error) throw error;
	
	if(status) console.log(status);
	if(data) console.log(data);

	/*Provider.grant({
		grant_type: 'refresh_token',
		refresh_token: data.refresh_token,
		client_id: '1',
		client_secret: '123'
	}, function(error, status, data){
		
		if(error) throw error;

		if(status) console.log(status);
		if(data) console.log(data);

	});*/

	console.log('\n');

	/*Provider.revokeToken(data.access_token, function(error, status, d){

		if(error) throw error;

		if(status) console.log(status);
		
		if(d) console.log(d);

		console.log('\n');

		Provider.canAccess(data.access_token, 'profile', function(error, status, data){
			
			if(error) throw error;

			if(status) console.log(status);
			if(data) console.log(data);

		});

	});

	/*setTimeout(function(){
		Provider.tokenInfo(data.access_token, function(error, info){

			if(error) throw error;

			console.log(info);

			console.log('\n');

			Provider.canAccess(data.access_token, 'profile', function(error, status, data){

				if(error) throw error;

				if(status) console.log(status);
				if(data) console.log(data);

			});

		});
	}, 6000);*/

});