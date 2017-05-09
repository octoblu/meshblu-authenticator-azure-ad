envalid       = require 'envalid'
MeshbluConfig = require 'meshblu-config'
base64        = require './src/helpers/base64-envalid'
Server        = require './src/server'

ENV_CONFIG = {
  PORT: envalid.num({ default: 80, devDefault: 6629 })
  AUTHENTICATOR_PRIVATE_KEY: base64(desc: 'Base64 encoded private key for meshblu')
  AUTHENTICATOR_NAMESPACE: envalid.str(desc: 'namespace for authenticator devices')
  AZURE_AD_URL: envalid.url(default: 'https://login.microsoftonline.com/common')
  CALLBACK_URL: envalid.url()
  CLIENT_ID: envalid.str(desc: 'specifies the client id of the application that is registered in Azure Active Directory.')
  CLIENT_SECRET: envalid.str(desc: 'secret used to establish ownership of the client Id.')
  RESOURCE: envalid.str(desc: 'the App ID URI of the web API (secured resource).')
  TENANT: envalid.str(desc: 'tenant domain (e.g.: contoso.onmicrosoft.com).')
}

class Command
  constructor: ({env}) ->
    env = envalid.cleanEnv env, ENV_CONFIG

    @server = new Server {
      clientID:      env.CLIENT_ID
      clientSecret:  env.CLIENT_SECRET
      callbackURL:   env.CALLBACK_URL
      meshbluConfig: new MeshbluConfig().toJSON()
      namespace:     env.AUTHENTICATOR_NAMESPACE
      port:          env.PORT
      privateKey:    env.AUTHENTICATOR_PRIVATE_KEY
      resource:      env.RESOURCE
      tenant:        env.TENANT
    }

  fatal: (error) =>
    console.error error.stack
    process.exit 1

  run: =>
    @server.run (error) =>
      return @fatal error if error?
      console.log "listening on: http://localhost:#{@server.address().port}"


module.exports = Command
