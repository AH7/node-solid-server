var assert = require('chai').assert

var utils = require('../lib/utils')

describe('Utility functions', function () {
  describe('pathBasename', function () {
    it('should return bar as relative path for /foo/bar', function () {
      assert.equal(utils.pathBasename('/foo/bar'), 'bar')
    })
    it('should return empty as relative path for /foo/', function () {
      assert.equal(utils.pathBasename('/foo/'), '')
    })
    it('should return empty as relative path for /', function () {
      assert.equal(utils.pathBasename('/'), '')
    })
    it('should return empty as relative path for empty path', function () {
      assert.equal(utils.pathBasename(''), '')
    })
    it('should return empty as relative path for undefined path', function () {
      assert.equal(utils.pathBasename(undefined), '')
    })
  })
  describe('uriToFilename', function () {
    it('should decode hex-encoded space', function () {
      assert.equal(utils.uriToFilename('uri%20', 'base/'), 'base/uri ')
    })
    it('should decode hex-encoded at sign', function () {
      assert.equal(utils.uriToFilename('film%4011', 'base/'), 'base/film@11')
    })
    it('should decode hex-encoded single quote', function () {
      assert.equal(utils.uriToFilename('quote%27', 'base/'), 'base/quote\'')
    })
  })
})
