{afterEach, beforeEach, describe, it} = global
{expect} = require 'chai'
fs = require 'fs'
path = require 'path'
shmock = require 'shmock'
AuthenticatorService = require '../../src/services/authenticator-service'


PRIVATE_KEY = fs.readFileSync path.join(__dirname, '../fixtures/privateKey.pem')

describe 'AuthenticatorService', ->
  beforeEach ->
    @microsoftonline = shmock()

    @sut = new AuthenticatorService
      meshbluConfig: {}
      namespace: 'foo'
      privateKey: PRIVATE_KEY
      publicKeysUrl: "http://localhost:#{@microsoftonline.address().port}"

  afterEach (done) ->
    @microsoftonline.close done

  it 'should exist', ->
    expect(@sut).to.exist
