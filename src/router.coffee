class Router
  constructor: ({ @authenticatorController }) ->
    throw new Error 'Router: requires authenticatorController' unless @authenticatorController?

  route: (app) =>
    app.get '/authenticate',          @authenticatorController.storeCallbackUrl, @authenticatorController.authenticate
    app.get '/authenticate/callback', @authenticatorController.verify, @authenticatorController.redirectToCallbackUrl

module.exports = Router
