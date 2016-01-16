# com-github-lucasrpb-oauth2
OAuth2 Provider "interface"

This provider interface handles all OAuth 2.0 specifications and has one more: limited device. This one is specially designed for handling authorization in limited devices, i.e, those that don't have a web browser to perform redirection. The mechanism is simple: user requests app instalation and a device code is generated. The user must log into his account in a web browser supported device, access the device authorization page (custom URL for your own application - this is up to you) and provide that device code to grant access to the original device. Having done that, as soon as the device pooled the web server and verified the granted authorization, the application can start to be used :) 

The file tests/memory-service.js is an example of in-memory implementation of OAuth 2.0 Provider. 

To test the different kinds of authorization you must execute the following command inside the root directory of this package: node tests/<authorization_type>, e.g.: node tests/web

That's all. Better documentation will be provided as soon as I could. 
