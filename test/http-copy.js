var assert = require('chai').assert
var fs = require('fs')
var request = require('request')
var path = require('path')
// Helper functions for the FS
var rm = require('./test-utils').rm

var solidServer = require('../index')

describe('HTTP COPY API', function () {
  this.timeout(10000)
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

  var address = 'https://localhost:3456/test'

  var ldpHttpsServer
  var ldp = solidServer.createServer({
    mount: '/test',
    root: path.join(__dirname, '/resources'),
    sslKey: path.join(__dirname, '/keys/key.pem'),
    sslCert: path.join(__dirname, '/keys/cert.pem'),
    webid: true
  })

  before(function (done) {
    ldpHttpsServer = ldp.listen(3456, done)
  })

  after(function () {
    if (ldpHttpsServer) ldpHttpsServer.close()
    // Clean up after COPY API tests
    return Promise.all([
      rm('/resources/sampleUser1Container/nicola-copy.jpg')
    ])
  })

  var userCredentials = {
    user1: {
      cert: fs.readFileSync(path.join(__dirname, '/keys/user1-cert.pem')),
      key: fs.readFileSync(path.join(__dirname, '/keys/user1-key.pem'))
    },
    user2: {
      cert: fs.readFileSync(path.join(__dirname, '/keys/user2-cert.pem')),
      key: fs.readFileSync(path.join(__dirname, '/keys/user2-key.pem'))
    }
  }

  function createOptions (method, url, user) {
    var options = {
      method: method,
      url: url,
      headers: {}
    }
    if (user) {
      options.agentOptions = userCredentials[user]
    }
    return options
  }

  it('should create the copied resource', function (done) {
    var copyFrom = '/resources/samplePublicContainer/nicola.jpg'
    var copyTo = '/resources/sampleUser1Container/nicola-copy.jpg'
    var uri = address + copyTo
    var options = createOptions('COPY', uri, 'user1')
    options.headers[ 'Source' ] = copyFrom
    request(uri, options, function (error, response) {
      assert.equal(error, null)
      assert.equal(response.statusCode, 201)
      assert.equal(response.headers[ 'location' ], copyTo)
      let destinationPath = path.join(__dirname, 'resources', copyTo)
      assert.ok(fs.existsSync(destinationPath),
        'Resource created via COPY should exist')
      done()
    })
  })

  it('should give a 404 if source document doesn\'t exist', function (done) {
    var copyFrom = '/resources/samplePublicContainer/invalid-resource'
    var copyTo = '/resources/sampleUser1Container/invalid-resource-copy'
    var uri = address + copyTo
    var options = createOptions('COPY', uri, 'user1')
    options.headers[ 'Source' ] = copyFrom
    request(uri, options, function (error, response) {
      assert.equal(error, null)
      assert.equal(response.statusCode, 404)
      done()
    })
  })

  it('should give a 400 if Source header is not supplied', function (done) {
    var copyTo = '/resources/sampleUser1Container/nicola-copy.jpg'
    var uri = address + copyTo
    var options = createOptions('COPY', uri, 'user1')
    request(uri, options, function (error, response) {
      assert.equal(error, null)
      assert.equal(response.statusCode, 400)
      done()
    })
  })
})
