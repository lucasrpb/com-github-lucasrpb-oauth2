/**
 * Token Authorization
 * @type {OAuth2Provider|exports|module.exports}
 */

var OAuth2Provider = require('../index');
var Service = require('./memory-service');

var Provider = OAuth2Provider.create(Service);

Provider.authorization({
	response_type: 'token',
	client_id: '1',
	redirect_uri: 'http://localhost:9000',
	scope: 'photos,profile',
	allow: '1',
	state: '211212%ausghuas',
	device_id: '1'
}, 'lucasrpb', function(error, status, data){
	
	if(error) throw error;

	if(status) console.log(status);
	if(data) console.log(data);

});