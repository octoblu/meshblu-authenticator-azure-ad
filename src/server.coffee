session                 = require 'cookie-session'
cookieParser            = require 'cookie-parser'
octobluExpress          = require 'express-octoblu'
http                    = require 'http'
passport                = require 'passport'
AzureAdOAuth2Strategy   = require 'passport-azure-ad-oauth2'
enableDestroy           = require 'server-destroy'

AuthenticatorController = require './controllers/authenticator-controller'
Router                  = require './router'
AuthenticatorService    = require './services/authenticator-service'

SESSION_SECRET='some-secret-that-does-not-really-matter'

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
    app.use cookieParser()
    app.use session @_sessionOptions()
    app.use passport.initialize()
    app.use passport.session()
    router = new Router { authenticatorController }
    router.route app

    @server = http.createServer app
    enableDestroy @server

  address: =>
    @server.address()

  run: (callback) =>
    @server.listen @port, callback

  _sessionOptions: =>
    return {
      secret: SESSION_SECRET
      resave: false
      saveUninitialized: true
      secure: process.env.NODE_ENV == 'production'
      maxAge: 60 * 60 * 1000
    }

module.exports = Server
