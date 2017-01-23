'use strict'

const path = require('path')
const url = require('url')
const KVPFileStore = require('kvplus-files')
const ResourceAuthenticator = require('oidc-rs')
const OIDCProvider = require('oidc-op')
const { MultiRpClient } = require('solid-multi-rp-client')

const debug = require('./debug')
const UserStore = require('./user-store')

class WebIdOidcAuth {

  static initConfig (argv) {
    let oidcProviderUri = argv.oidcProviderUri || argv.serverUri
    if (!oidcProviderUri) {
      throw new TypeError('oidcProviderUri required for auth initialization')
    }

    let authCallbackUri = url.resolve(oidcProviderUri, '/api/oidc/rp')
    let postLogoutUri = url.resolve(oidcProviderUri, '/signed_out.html')

    let dbPath = argv.dbPath || './db/oidc'
    // RelyingParty client store path (results in 'db/oidc/rp/clients')
    let rpClientStorePath = path.resolve(dbPath, 'rp')
    // User store path (results in 'db/oidc/user/['users', 'users-by-email'])
    let userStorePath = path.resolve(dbPath, 'users')
    // Identity Provider store path (db/oidc/op/['codes', 'clients', 'tokens', 'refresh'])
    let opStorePath = path.resolve(dbPath, 'op')

    let config = {
      serverUri: argv.serverUri,
      saltRounds: argv.saltRounds,  // bcrypt password salt rounds
      oidcProviderUri,
      dbPath,
      rpClientStorePath,
      userStorePath,
      opStorePath,
      oidc: {
        'issuer': oidcProviderUri,
        'redirect_uri': authCallbackUri,
        'post_logout_redirect_uris': [ postLogoutUri ]
      }
    }
    return config
  }

  static initMultiRpClient (config) {
    let rpClientStore = new KVPFileStore({
      path: config.rpClientStorePath,
      collections: ['clients']
    })
    rpClientStore.initCollections()  // sync, ensure storage dirs created

    let multiRpClient = new MultiRpClient({
      localConfig: config.oidc,
      store: rpClientStore
    })
    return multiRpClient
  }

  static initResourceAuthenticator () {
    let rsOptions = {  // oidc-rs
      defaults: { handleErrors: false, optional: true, query: true }
    }
    return new ResourceAuthenticator(rsOptions)
  }

  static initUserStore (config) {
    let userStore = new UserStore({ path: config.userStorePath })
    userStore.initCollections()  // sync, ensure storage dirs created
    return userStore
  }

  /**
   * @method fromServerConfig
   *
   * @param [argv={}] {Object} Solid server options hashmap
   * @param [argv.serverUri] {string} External URI of this Solid server, fully
   *   qualified. For example: 'https://localhost:8443' or 'https://databox.me'
   * @param [argv.oidcProviderUri] {string} URI of the OpenID Connect Provider
   *   (defaults to `config.serverUri`, since it is typically embedded in solid-server).
   * @param [argv.dbPath='./db'] {string} Folder in which to store the auth
   *   persistence (users, clients, tokens) store.
   * @returns {{auth: *, clients: *, config: *, users: *}}
   */
  static fromServerConfig (argv) {
    debug.oidc('Initializing oidc clients at startup.')

    let config = WebIdOidcAuth.initConfig(argv)

    let oidc = {
      auth: WebIdOidcAuth.initResourceAuthenticator(),
      clients: WebIdOidcAuth.initMultiRpClient(config),
      provider: WebIdOidcAuth.initProvider(config),
      users: WebIdOidcAuth.initUserStore(config)
    }
    return oidc
  }

  static initProvider (config) {
    // Minimal provider
    // let providerConfig = require(path.join(__dirname, '../provider.json'))
    // let provider = new OIDCProvider(providerConfig)
    let provider = new OIDCProvider({
      issuer: config.oidcProviderUri
    })
    // INITIALIZE THE KEY CHAIN, SERIALIZE, PERSIST
    // provider.initializeKeyChain(providerConfig.keys)
    provider.initializeKeyChain()
      .then(keys => {
        // fs.writeFileSync('provider.json', JSON.stringify(provider, null, 2))
        console.log('Provider keychain initialized')
      })
      .catch(err => {
        debug.oidc(err)
        console.log(err)
        throw err
      })
    let oidcStore = new KVPFileStore({
      path: './db/oidc',
      collections: ['codes', 'clients', 'tokens', 'refresh']
    })
    oidcStore.initCollections()
    provider.inject({ backend: oidcStore })
    provider.inject({
      host: {
        // This gets called from OIDC Provider's /authorize endpoint
        authenticate: (authRequest) => {
          console.log('AUTHENTICATE injected method')
          let session = authRequest.req.session
          if (session.identified && session.userId) {
            authRequest.subject = {
              _id: session.userId  // put webId into the IDToken's subject claim
            }
          } else {
            // User not authenticated, send them to signin
            let signinUrl = url.parse(url.resolve(config.oidcProviderUri, '/signin/'))
            signinUrl.query = authRequest.req.query
            signinUrl = url.format(signinUrl)
            authRequest.subject = null
            console.log('Redirecting to /signin', signinUrl)
            authRequest.res.redirect(signinUrl)
          }
          return authRequest
        },
        obtainConsent: (authRequest) => {
          if (authRequest.subject) {
            authRequest.consent = true
            authRequest.scope = authRequest.params.scope
            console.log('OBTAINED CONSENT')
          }
          return authRequest
        },
        logout: (logoutRequest) => {
          let req = logoutRequest.req
          req.session.accessToken = ''
          req.session.refreshToken = ''
          // req.session.issuer = ''
          req.session.userId = ''
          req.session.identified = false
          // Inject post_logout_redirect_uri here? (If Accept: text/html)
          console.log('LOGOUT behavior')
          return logoutRequest
        }
      }
    })
    return provider
  }
}

module.exports = WebIdOidcAuth
