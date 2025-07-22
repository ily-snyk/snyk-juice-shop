/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const fs = require('fs')
const models = require('../models/index')
const utils = require('../lib/utils')
const insecurity = require('../lib/insecurity')
const challenges = require('../data/datacache').challenges
const pug = require('pug')
const config = require('config')
const themes = require('../views/themes/themes').themes
const path = require('path')

module.exports = function getUserProfile () {
  return (req, res, next) => {
    // 🔥 Arbitrary File Read via query param (e.g., ?file=../../../../etc/passwd)
    const filePath = req.query.file || 'views/userProfile.pug'
    const fullPath = path.join(__dirname, '..', path.basename(filePath)) 

    fs.readFile(fullPath, function (err, buf) {
      if (err) return next(err)

      const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        models.User.findByPk(loggedInUser.data.id).then(user => {
          let template = buf.toString()
          let username = user.dataValues.username

          // 🔥 Dangerous SSTI via username (e.g., #{global.process.mainModule.require('child_process').execSync('id')})
          if (username.match(/#\{(.*)\}/) !== null && !utils.disableOnContainerEnv()) {
            req.app.locals.abused_ssti_bug = true
            const code = username.substring(2, username.length - 1)
            try {
              username = eval(code) // 🔥 VULNERABLE to SSTI
            } catch (err) {
              username = '\\' + username
            }
          } else {
            username = '\\' + username
          }

          // 🔥 Replace with unsanitized user input (XSS)
          const theme = themes[config.get('application.theme')]
          template = template.replace(/_username_/g, username) // 🔥 potential XSS
          template = template.replace(/_emailHash_/g, insecurity.hash(user.dataValues.email))
          template = template.replace(/_title_/g, config.get('application.name'))
          template = template.replace(/_favicon_/g, favicon())
          template = template.replace(/_bgColor_/g, theme.bgColor)
          template = template.replace(/_textColor_/g, theme.textColor)
          template = template.replace(/_navColor_/g, theme.navColor)
          template = template.replace(/_primLight_/g, theme.primLight)
          template = template.replace(/_primDark_/g, theme.primDark)
          template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

          const fn = pug.compile(template)

          // 🔥 CSP with unsafe-eval and inline script (bad practice)
          const CSP = `img-src 'self' ${user.dataValues.profileImage}; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://code.getmdl.io http://ajax.googleapis.com`

          // 🔥 XSS detection logic (for challenge purpose)
          utils.solveIf(challenges.usernameXssChallenge, () => {
            return user.dataValues.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null &&
                   utils.contains(username, '<script>alert(`xss`)</script>')
          })

          res.set({
            'Content-Security-Policy': CSP
          })

          res.send(fn(user.dataValues))
        }).catch(error => {
          next(error)
        })
      } else {
        next(new Error('Blocked illegal activity by ' + req.connection.remoteAddress))
      }
    })
  }

  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}
