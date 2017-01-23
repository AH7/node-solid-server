'use strict'
/**
 * OIDC Relying Party API handler module.
 */

const express = require('express')
const path = require('path')
const debug = require('../debug')
const util = require('../utils')
const addLink = require('../header').addLink
const error = require('../http-error')

module.exports.api = api
module.exports.resumeUserFlow = resumeUserFlow
module.exports.oidcIssuerHeader = oidcIssuerHeader

/**
 * OIDC Relying Party API middleware.
 * Usage:
 *
 *   ```
 *   app.use('/api/oidc', oidcHandler.api(oidc))
 *   ```
 * @method api
 * @return {Router} Express router
 */
function api (oidc) {
  // router.use('/api/oidc', oidcHandler.api(oidc))

  const router = express.Router('/')

  // Return 'oidc.issuer' link rel header on OPTIONS requests (for discovery)
  router.options('*', oidcIssuerHeader)

  // The /rp (relying party) callback is called at the end of the OIDC signin
  // process
  router.get('/rp/:issuer_id',
    // Authenticate the RP callback (exchange code for id token)
    authCodeFlowCallback(oidc),
    // Redirect the user back to returnToUrl (that they were requesting before
    //  being forced to sign in)
    resumeUserFlow
  )

  // This is where the OIDC-enabled signup/signin apps live
  router.use('/', express.static(path.join(__dirname, '../static/oidc')))
  // Sign in (provider discovery) / sign out API

  // Initialize the OIDC Identity Provider routes/api
  let oidcApi = require('oidc-op-express')(oidc.provider)
  router.use('/', oidcApi)

  return router
}

/**
 * Advertises the OIDC Issuer endpoint by returning a Link Relation header
 * of type `oidc.issuer` on an OPTIONS request.
 * Added to avoid an additional request to the serviceCapability document.
 * Usage (in create-app.js):
 *   ```
 *   app.options('*', oidcHandler.oidcIssuerHeader)
 *   ```
 * @param req
 * @param res
 * @param next
 */
function oidcIssuerHeader (req, res, next) {
  let oidcIssuerEndpoint = req.app.locals.oidc.config.issuer
  addLink(res, oidcIssuerEndpoint, 'oidc.issuer')
  next()
}

function authCodeFlowCallback (oidc) {
  return (req, res, next) => {
    debug.oidc('in authCallback():')
    debug.oidc('code: ' + req.query.code + ', exchanging via client.token()')
    if (!req.params.issuer_id) {
      return next(error(400, 'Invalid auth response uri - missing issuer id'))
    }
    let issuer = decodeURIComponent(req.params.issuer_id)
    oidc.clients.clientForIssuer(issuer)
      .then((oidcClient) => {
        debug.oidc('authCodeFlowCallback: Client initialized')
        let url = util.fullUrlForReq(req)
        return oidcClient.validateResponse(url, req.session)
      })
      .then((oidcResponse) => {
        let webId = oidcResponse.decoded.payload.sub
        let accessToken = oidcResponse.params.access_token
        let refreshToken = oidcResponse.params.refresh_token
        req.session.accessToken = accessToken
        req.session.refreshToken = refreshToken
        // req.session.issuer = issuer
        req.session.userId = webId
        req.session.identified = true
        next()
      })
      .catch((err) => {
        debug.oidc(err)
        next(error(400, err))
      })
  }
}

/**
 * Redirects the user back to their original requested resource, at the end
 * of the OIDC authentication process.
 * @method resumeUserFlow
 */
function resumeUserFlow (req, res, next) {
  debug.oidc('In resumeUserFlow handler:')

  if (req.session.returnToUrl) {
    let returnToUrl = req.session.returnToUrl
    if (req.session.accessToken) {
      returnToUrl += '?access_token=' + req.session.accessToken
    }
    debug.oidc('  Redirecting to ' + returnToUrl)
    delete req.session.returnToUrl
    return res.redirect(302, returnToUrl)
  }
  res.send('Resume User Flow (failed)')
  // next()
}
