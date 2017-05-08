envalid  = require 'envalid'
isString = require 'lodash/fp/isString'

base64 = envalid.makeValidator (value) =>
  return throw new Error 'Expected a string' unless isString value
  return new Buffer(value, 'base64').toString('utf8')

module.exports = base64
