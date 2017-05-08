http                    = require 'http'
enableDestroy           = require 'server-destroy'
octobluExpress          = require 'express-octoblu'
Router                  = require './router'
AuthenticatorService    = require './services/authenticator-service'
AuthenticatorController = require './controllers/authenticator-controller'

class Server
  constructor: ({ disableLogging, logFn, meshbluConfig, privateKey }) ->
    throw new Error 'Missing required parameter: meshbluConfig' unless meshbluConfig?
    throw new Error 'Missing required parameter: privateKey' unless privateKey?

    authenticatorService    = new AuthenticatorService { meshbluConfig, privateKey }
    authenticatorController = new AuthenticatorController { authenticatorService }

    app = octobluExpress { logFn, disableLogging }
    router = new Router { authenticatorController }
    router.route app

    @server = http.createServer app
    enableDestroy @server

  address: =>
    @server.address()

  run: (callback) =>
    @server.listen @port, callback

module.exports = Server
