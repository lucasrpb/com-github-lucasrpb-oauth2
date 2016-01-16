/**
 * Web Application Authorization
 * @type {OAuth2Provider|exports|module.exports}
 */
var OAuth2Provider = require('../index');
var Service = require('./memory-service');

var Provider = OAuth2Provider.create(Service);

Provider.authorization({
	response_type: 'code',
	client_id: '1',
	client_secret: '123',
	redirect_uri: 'http://localhost:9000',
	scope: 'photos,profile',
	allow: '1',
	state: '211212%ausghuas'
}, 'lucasrpb', function(error, status, data){

	if(error) throw error;

	if(status) console.log(status);
	if(data) console.log(data);

	console.log('\n');

	Provider.grant({
		grant_type: 'authorization_code',
		code: data.code,
		client_id: '1',
		client_secret: '123',
		redirect_uri: 'http://localhost:9000'
	}, function(error, status, data){

		if(error) throw error;

		if(status) console.log(status);
		if(data) console.log(data);

	});

});