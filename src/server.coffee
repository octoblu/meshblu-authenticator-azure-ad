http                    = require 'http'
enableDestroy           = require 'server-destroy'
octobluExpress          = require 'express-octoblu'
passport                = require 'passport'
AzureAdOAuth2Strategy   = require 'passport-azure-ad-oauth2'

AuthenticatorController = require './controllers/authenticator-controller'
Router                  = require './router'
AuthenticatorService    = require './services/authenticator-service'

class Server
  constructor: ({ clientID, clientSecret, callbackURL, disableLogging, logFn, meshbluConfig, namespace, @port, privateKey, resource, tenant }) ->
    throw new Error 'Missing required parameter: clientID' unless clientID?
    throw new Error 'Missing required parameter: clientSecret' unless clientSecret?
    throw new Error 'Missing required parameter: callbackURL' unless callbackURL?
    throw new Error 'Missing required parameter: meshbluConfig' unless meshbluConfig?
    throw new Error 'Missing required parameter: namespace' unless namespace?
    throw new Error 'Missing required parameter: privateKey' unless privateKey?
    throw new Error 'Missing required parameter: resource' unless resource?
    throw new Error 'Missing required parameter: tenant' unless tenant?

    authenticatorService    = new AuthenticatorService { meshbluConfig, namespace, privateKey }
    authenticatorController = new AuthenticatorController { authenticatorService }

    passport.serializeUser   (user, callback) => callback null, user
    passport.deserializeUser (user, callback) => callback null, user
    passport.use new AzureAdOAuth2Strategy({ clientID, clientSecret, callbackURL, resource, tenant }, authenticatorService.authenticate)

    app = octobluExpress { logFn, disableLogging }
    app.use passport.initialize()
    router = new Router { authenticatorController }
    router.route app

    @server = http.createServer app
    enableDestroy @server

  address: =>
    @server.address()

  run: (callback) =>
    @server.listen @port, callback

module.exports = Server
