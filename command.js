#!/usr/bin/env node

require('coffeescript/register')
const Command = require('./command.coffee')
const command = new Command({argv: process.argv, env: process.env})
command.run()

