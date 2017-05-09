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

  describe '->_publicKeyForKid', ->
    describe 'when called without a kid', ->
      beforeEach (done) ->
        @sut._publicKeyForKid null, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'expected kid to be a non-empty string'

    describe 'when called with a non-string kid', ->
      beforeEach (done) ->
        @sut._publicKeyForKid 1, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'expected kid to be a non-empty string'

    describe 'when called with an empty string kid', ->
      beforeEach (done) ->
        @sut._publicKeyForKid '', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'expected kid to be a non-empty string'

    describe 'when called with a kid but the server returns a 404', ->
      beforeEach (done) ->
        @sut._publicKeyForKid 'asdf', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'non 2xx response from microsoftonline: 404'

    describe "when called with a kid that the server doesn't know about", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "fdsa"
              x5c: ['public-key']
            }]
          }

        @sut._publicKeyForKid 'asdf', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Response from microsoftonline did not contain the kid'

    describe "when server returns a malformed response", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "asdf"
            }]
          }

        @sut._publicKeyForKid 'asdf', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Response from microsoftonline was malformed'

    describe "when called with a kid that the server knows about", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "asdf"
              x5c: ['public-key']
            }]
          }

        @sut._publicKeyForKid 'asdf', (error, @publicKey) => done(error)

      it 'should yield the public key', ->
        expect(@publicKey).to.deep.equal '''
          -----BEGIN CERTIFICATE-----
          public-key
          -----END CERTIFICATE-----
        '''

    describe "when the server returns a different public key", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "asdf"
              x5c: ['very-public-key']
            }]
          }

        @sut._publicKeyForKid 'asdf', (error, @publicKey) => done(error)

      it 'should yield the different public key', ->
        expect(@publicKey).to.deep.equal '''
          -----BEGIN CERTIFICATE-----
          very-public-key
          -----END CERTIFICATE-----
        '''

    describe "when called with a different kid that the server knows about", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "lkj"
              x5c: ['public-key']
            }]
          }

        @sut._publicKeyForKid 'lkj', (error, @publicKey) => done(error)

      it 'should yield the different public key', ->
        expect(@publicKey).to.deep.equal '''
          -----BEGIN CERTIFICATE-----
          public-key
          -----END CERTIFICATE-----
        '''

    describe "when the server returns two keys", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "wrong"
              x5c: ['wrong-public-key']
            }, {
              kid: "asdf"
              x5c: ['public-key']
            }]
          }

        @sut._publicKeyForKid 'asdf', (error, @publicKey) => done(error)

      it 'should yield the different public key', ->
        expect(@publicKey).to.deep.equal '''
          -----BEGIN CERTIFICATE-----
          public-key
          -----END CERTIFICATE-----
        '''
