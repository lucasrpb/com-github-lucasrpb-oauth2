/**
 * Client Credentials Authorization (application authorization)
 * @type {OAuth2Provider|exports|module.exports}
 */
var OAuth2Provider = require('../index');
var Service = require('./memory-service');

var Provider = OAuth2Provider.create(Service);

Provider.grant({
	grant_type: 'client_credentials',
	client_id: '1',
	client_secret: '123',
	scope: 'profile'

}, function(error, status, data){
	
	if(error) throw error;
	
	if(status) console.log(status);
	if(data) console.log(data);

});