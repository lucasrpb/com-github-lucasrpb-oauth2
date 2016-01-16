/**
 * Limited Device Authorization (consoles, smartTVs, etc)
 * @type {OAuth2Provider|exports|module.exports}
 */
var OAuth2Provider = require('../index');
var Service = require('./memory-service');

var Provider = OAuth2Provider.create(Service);

// Generates the confirmation code to user confirm in a device with web browser
Provider.authorization({
	response_type: 'device_code',
	client_id: '1',
	scope: 'photos,profile',
	device_id: '1'
}, null, function(error, status, data){
		
	if(error) throw error;
	
	if(status) console.log(status);
	if(data) console.log(data);

	// Simulating the device confirmation by the user...
	Provider.confirmDevice(data.code, 'lucasrpb', function(error, ok){

		if(error) throw error;
								
		console.log('ok: '+ok);
		console.log('\n');

		// Change the temporary code by the access token
		Provider.grant({
			grant_type: 'limited_device',
			client_id: '1',
			code: data.code
		}, function(error, status, data){

			if(error) throw error;

			if(status) console.log(status);
			if(data) console.log(data);
			
		});

	});

});
