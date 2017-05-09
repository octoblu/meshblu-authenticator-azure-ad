jwt = require 'jsonwebtoken'
_   = require 'lodash'
{ DeviceAuthenticator } = require 'meshblu-authenticator-core'
MeshbluHttp = require 'meshblu-http'
request     = require 'request'
debug       = require('debug')('meshblu-authenticator-azure-ad:authenticator-service')

DEFAULT_PASSWORD = 'no-need-for-this'
PUBLIC_KEYS_URL  = 'https://login.microsoftonline.com/common/discovery/keys'

class AuthenticatorService
  constructor: ({ meshbluConfig, @namespace, privateKey, @publicKeysUrl }={}) ->
    throw new Error 'Missing required parameter: meshbluConfig' unless meshbluConfig?
    throw new Error 'Missing required parameter: namespace' unless @namespace?
    throw new Error 'Missing required parameter: privateKey' unless privateKey?

    @publicKeysUrl ?= PUBLIC_KEYS_URL

    @meshbluHttp = new MeshbluHttp meshbluConfig
    @meshbluHttp.setPrivateKey privateKey

    @deviceModel = new DeviceAuthenticator {
      authenticatorUuid: meshbluConfig.uuid
      authenticatorName: 'Meshblu Authenticator Azure AD'
      meshbluHttp: @meshbluHttp
    }

  authenticate: (accessToken, refresh_token, params, callback) =>
    {header} = jwt.decode accessToken, complete: true
    @_publicKeyForKid header.kid, (error, publicKey) =>
      return callback error if error?

      jwt.verify accessToken, publicKey, algorithms: ['RS256'], (error, profile) =>
        return callback error if error?
        @_ensureUser {
          email:     profile.unique_name
          firstName: profile.given_name
          lastName:  profile.family_name
        }, callback

  _createSearchId: ({ email }) =>
    debug '_createSearchId', { email }
    email = _.toLower email
    return "#{@authenticatorUuid}:#{@namespace}:#{email}"

  _createUserDevice: ({ email, firstName, lastName }, callback) =>
    debug '_createUserDevice', { email, firstName, lastName }
    email = _.toLower email
    searchId = @_createSearchId { email }
    query = {}
    query['meshblu.search.terms'] = { $in: [searchId] }
    @deviceModel.create {
      query: query
      data:
        user:
          metadata: { firstName, lastName, email }
        email: email
        name: "#{firstName} #{lastName}"
      user_id: email
      secret: DEFAULT_PASSWORD
    }, (error, device) =>
      return callback error if error?
      @_updateSearchTerms { device, searchId }, (error) =>
        return callback error if error?
        callback null, device

  _ensureUser: ({ email, firstName, lastName }, callback) =>
    debug '_ensureUser', { email, firstName, lastName }
    @_validateRequest { email, firstName, lastName }, (error) =>
      return callback error if error?
      @_maybeCreateDevice { email, firstName, lastName }, (error, device) =>
        return callback error if error?
        @_generateToken { device }, callback


  _findUserDevice: ({ email }, callback) =>
    debug '_maybeCreateDevice', { email }
    searchId = @_createSearchId { email }
    query = {}
    query['meshblu.search.terms'] = { $in: [searchId] }
    @deviceModel.findVerified { query, password: DEFAULT_PASSWORD }, callback

  _generateToken: ({ device }, callback) =>
    debug '_generateToken', { uuid: device.uuid }
    @meshbluHttp.generateAndStoreToken device.uuid, callback

  _maybeCreateDevice: ({ email, firstName, lastName }, callback) =>
    debug '_maybeCreateDevice', { email, firstName, lastName }
    @_findUserDevice { email }, (error, device) =>
      return callback error if error?
      return callback null, device if device?
      @_createUserDevice { email, firstName, lastName }, callback

  _publicKeyForKid: (kid, callback) =>
    return callback new Error 'expected kid to be a non-empty string' unless _.isString(kid) && !_.isEmpty(kid)

    request.get @publicKeysUrl, json: true, (error, response, body) =>
      return callback error if error?
      return callback new Error "non 2xx response from microsoftonline: #{response.statusCode}" if response.statusCode > 299

      key = _.find body.keys, {kid: kid}
      return callback new Error 'Response from microsoftonline did not contain the kid' unless key?

      publicKey = _.get(key, 'x5c.0')
      return callback new Error 'Response from microsoftonline was malformed' unless publicKey?
      return callback null, """
        -----BEGIN CERTIFICATE-----
        #{publicKey}
        -----END CERTIFICATE-----
      """

  _updateSearchTerms: ({ device, searchId }, callback) =>
    debug '_updateSearchTerms', { searchId }
    query =
      $addToSet:
        'meshblu.search.terms': searchId
    @meshbluHttp.updateDangerously device.uuid, query, callback

  _validateRequest: ({ email, firstName, lastName }, callback) =>
    debug '_validateRequest', { email, firstName, lastName }
    return callback @_createError 'Last Name required', 422 if _.isEmpty lastName
    return callback @_createError 'First Name required', 422 if _.isEmpty firstName
    return callback @_createError 'Email required', 422 if _.isEmpty email
    callback null

module.exports = AuthenticatorService
