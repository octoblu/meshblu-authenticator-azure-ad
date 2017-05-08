envalid       = require 'envalid'
MeshbluConfig = require 'meshblu-config'
base64        = require './src/helpers/base64-envalid'
Server        = require './src/server'

ENV_CONFIG = {
  PORT: envalid.num({ default: 80, devDefault: 6629 })
  AUTHENTICATOR_PRIVATE_KEY: base64 { desc: 'Base64 encoded private key for meshblu' }
  AZURE_AD_URL: envalid.url({ default: 'https://login.microsoftonline.com/common' })
  REDIRECT_URL: envalid.url()
  CLIENT_ID: envalid.str()
  CLIENT_SECRET: envalid.str()
}

class Command
  constructor: ({env}) ->
    env = envalid.cleanEnv env, ENV_CONFIG

    @server = new Server {
      meshbluConfig: new MeshbluConfig().toJSON()
      privateKey:    env.AUTHENTICATOR_PRIVATE_KEY
    }

  fatal: (error) =>
    console.error error.stack
    process.exit 1

  run: =>
    @server.run (error) =>
      return @fatal error if error?
      console.log "listening on: http://localhost:#{@server.address().port}"


module.exports = Command
