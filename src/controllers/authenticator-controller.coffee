passport = require 'passport'
url      = require 'url'

class AuthenticatorController
  constructor: ({}) ->
    @authenticate = passport.authenticate('azure_ad_oauth2')
    @verify       = passport.authenticate('azure_ad_oauth2', failureRedirect: '/')

  redirectToCallbackUrl: (request, response) =>
    { callbackUrl } = request.cookies
    { uuid, token } = request.user

    return response.redirect @_rebuildUrl { callbackUrl, uuid, token } if callbackUrl?
    response.send request.user

  storeCallbackUrl: (request, response, next) =>
    { callbackUrl } = request.query
    response.cookie 'callbackUrl', callbackUrl, { maxAge: 60 * 60 * 1000 }
    next()

  _rebuildUrl: ({ callbackUrl, uuid, token }) =>
    uriParams = url.parse callbackUrl, true
    delete uriParams.search
    uriParams.query ?= {}
    uriParams.query.uuid = uuid
    uriParams.query.token = token
    return url.format uriParams

module.exports = AuthenticatorController
