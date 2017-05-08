class Router
  constructor: ({ @authenticatorController }) ->
    throw new Error 'Router: requires authenticatorController' unless @authenticatorController?

  route: (app) =>
    # app.get '/authenticate',          @authenticatorController.authenticate
    # app.get '/authenticate/callback', @authenticatorController.ensureUser

module.exports = Router
