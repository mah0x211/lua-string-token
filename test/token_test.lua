require('luacov')
local testcase = require('testcase')
local assert = require('assert')
local hmacsha224 = require('hmac').sha224
local token = require('string.token')

local function hmacsha(secret, msg)
    local ctx = hmacsha224(secret)
    ctx:update(msg)
    return ctx:final()
end

function testcase.create()
    -- test that create a token
    local s = assert(token.create('foobar'))
    -- confirm
    local shahex_len = 224 / 8 * 2
    local hash = string.sub(s, 1, shahex_len)
    local msg = string.sub(s, shahex_len + 2)
    assert.equal(hash, hmacsha('foobar', msg))
    assert.equal(#msg, 32)

    -- test that create a token with nbyte length of random string
    s = assert(token.create('foobar', 16))
    -- confirm
    hash = string.sub(s, 1, shahex_len)
    msg = string.sub(s, shahex_len + 2)
    assert.equal(hash, hmacsha('foobar', msg))
    assert.equal(#msg, 16)

    -- test that throws error if invalid secret
    local err = assert.throws(token.create, {})
    assert.match(err, 'secret must be string')

    -- test that throws error if invalid nbyte
    err = assert.throws(token.create, 'hello', 'world')
    assert.match(err, 'nbyte must be positive-integer')
end

function testcase.verify()
    local s = assert(token.create('foobar'))

    -- test that verify a token
    assert.is_true(token.verify('foobar', s))

    -- test that returns false
    assert.is_false(token.verify('foobar', 'invalid_token'))

    -- test that throws error if invalid secret
    local err = assert.throws(token.verify, {})
    assert.match(err, 'secret must be string')

    -- test that throws error if invalid token
    err = assert.throws(token.verify, 'hello', {})
    assert.match(err, 'token must be string')
end
