module.exports = createApp

var express = require('express')
var session = require('express-session')
const favicon = require('serve-favicon')
var uuid = require('uuid')
var cors = require('cors')
var LDP = require('./ldp')
var LdpMiddleware = require('./ldp-middleware')
var proxy = require('./handlers/proxy')
var IdentityProvider = require('./identity-provider')
var vhost = require('vhost')
var path = require('path')
var EmailService = require('./email-service')
const url = require('url')
const AccountRecovery = require('./account-recovery')
const capabilityDiscovery = require('./capability-discovery')
const bodyParser = require('body-parser')
const API = require('./api')
// const debug = require('./debug')
const WebIdTlsAuth = require('./handlers/auth-webid-tls')
const oidcHandler = require('./handlers/auth-webid-oidc')
const WebIdOidcAuth = require('./auth-webid-oidc')

const corsSettings = cors({
  methods: [
    'OPTIONS', 'HEAD', 'GET', 'PATCH', 'POST', 'PUT', 'DELETE'
  ],
  exposedHeaders: 'Authorization, User, Location, Link, Vary, Last-Modified, ETag, Accept-Patch, Accept-Post, Updates-Via, Allow, Content-Length',
  credentials: true,
  maxAge: 1728000,
  origin: true,
  preflightContinue: true
})

function createApp (argv = {}) {
  var ldp = new LDP(argv)
  var app = express()

  app.use(favicon(path.join(__dirname, '../static/favicon.ico')))
  app.use(corsSettings)

  app.options('*', (req, res, next) => {
    res.status(204)
    next()
  })

  // check if we have master ACL or not
  var masterAcl
  var checkMasterAcl = function (req, callback) {
    if (masterAcl) {
      return callback(true)
    }

    ldp.exists(req.hostname, '/' + ldp.suffixAcl, function (err) {
      if (!err) {
        masterAcl = true
      }
      callback(!err)
    })
  }

  // Setting options as local variable
  app.locals.ldp = ldp
  app.locals.appUrls = argv.apps // used for service capability discovery
  app.locals.rootUri = argv.serverUri

  if (argv.email && argv.email.host) {
    app.locals.email = new EmailService(argv.email)
  }

  // Set X-Powered-By
  app.use((req, res, next) => {
    res.set('X-Powered-By', 'solid-server')
    next()
  })

  // Set default Allow methods
  app.use((req, res, next) => {
    res.set('Allow', 'OPTIONS, HEAD, GET, PATCH, POST, PUT, DELETE')
    next()
  })

  app.use('/', capabilityDiscovery())

  // Session
  app.use(session(sessionSettings(ldp, argv.uri)))

  // OpenID Connect Auth
  if (ldp.webid && ldp.auth === 'oidc') {
    let oidc = WebIdOidcAuth.fromServerConfig(argv)
    app.locals.oidc = oidc

    // Initialize the OIDC Identity Provider routes/api
    app.use('/', oidcHandler.api(oidc))

    // Enforce authentication with WebID-OIDC on all LDP routes
    app.use('/', oidc.auth.authenticate())
  } else if (ldp.webid && ldp.auth === 'tls') {
    // Enforce authentication with WebID-TLS on all LDP routes
    app.use('/', WebIdTlsAuth.authenticate())
  }

  // Adding proxy
  if (ldp.proxy) {
    proxy(app, ldp.proxy)
  }

  if (ldp.webid) {
    var accountRecovery = AccountRecovery({ redirect: '/' })
    // adds GET /api/accounts/recover
    // adds POST /api/accounts/recover
    // adds GET /api/accounts/validateToken
    app.use('/api/accounts/', accountRecovery)
  }

  // Adding Multi-user support
  if (ldp.webid) {
    var idp = IdentityProvider({
      store: ldp,
      suffixAcl: ldp.suffixAcl,
      suffixMeta: ldp.suffixMeta,
      settings: 'settings',
      inbox: 'inbox',
      auth: ldp.auth
    })

    var needsOverwrite = function (req, res, next) {
      checkMasterAcl(req, function (found) {
        if (!found && !ldp.idp) {
          // this allows IdentityProvider to overwrite root acls
          idp.middleware(true)(req, res, next)
        } else if (ldp.idp) {
          idp.middleware(false)(req, res, next)
        } else {
          next()
        }
      })
    }

    // adds POST /api/accounts/new
    // adds POST /api/accounts/newCert
    app.get('/', idp.get.bind(idp))
    app.post(['/signin', '/api/accounts/signin'],
      bodyParser.urlencoded({ extended: false }), API.accounts.signin())
    app.post('/api/accounts/discover',
      bodyParser.urlencoded({ extended: false }), API.accounts.discoverProvider())
    app.use('/api/accounts', needsOverwrite)

    app.post('/api/messages', WebIdTlsAuth.authenticate(), bodyParser.urlencoded({ extended: false }), API.messages.send())
  }

  if (argv.apiApps) {
    app.use('/api/apps', express.static(argv.apiApps))
  }

  if (ldp.idp) {
    app.use(vhost('*', LdpMiddleware(corsSettings)))
  }

  app.get('/', function (req, res, next) {
    // Do not bother showing html page can't be read
    if (!req.accepts('text/html') || !ldp.webid) {
      return next()
    }

    checkMasterAcl(req, function (found) {
      if (!found) {
        res.set('Content-Type', 'text/html')
        var signup = path.join(__dirname, '../static/signup.html')
        res.sendFile(signup)
      } else {
        next()
      }
    })
  })
  app.use('/', LdpMiddleware(corsSettings))

  return app
}

/**
 * @method sessionSettings
 * @param ldp {LDP}
 * @param rootUri {string}
 * @return {Object} `express-session` settings object
 */
function sessionSettings (ldp, rootUri) {
  let sessionSettings = {
    secret: ldp.secret || uuid.v1(),
    saveUninitialized: false,
    resave: false,
    rolling: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000
    }
  }
  // Cookies should set to be secure if https is on
  if (ldp.webid || ldp.idp) {
    sessionSettings.cookie.secure = true
  }
  // Determine the cookie domain
  if (rootUri) {
    let hostname = url.parse(rootUri).hostname
    if (hostname.split('.').length > 1) {
      // For single-level domains like 'localhost', do not set the cookie domain
      // See section on 'domain' attribute at https://curl.haxx.se/rfc/cookie_spec.html
      let cookieDomain = '.' + hostname
      sessionSettings.cookie.domain = cookieDomain
    }
  }
  return sessionSettings
}
