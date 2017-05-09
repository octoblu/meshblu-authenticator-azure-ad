passport = require 'passport'

class AuthenticatorController
  constructor: ({}) ->
    @authenticate = passport.authenticate('azure_ad_oauth2')
    @verify       = passport.authenticate('azure_ad_oauth2', failureRedirect: '/')

  finish: (request, response) =>
    response.send request.user

module.exports = AuthenticatorController
