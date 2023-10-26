--
-- Copyright (C) 2022 Masatoshi Fukunaga
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--
local sub = string.sub
local type = type
local hmacsha = require('hmac').sha224
local randstr = require('string.random')
-- constants
-- 32 byte = 256 bit / 8 bit
local DATA_LEN = 256 / 8
-- 56 byte = SHA-224(224 bit) / 8 bit * 2(HEX)
local SHA_LEN = 224 / 8 * 2
-- SHA_LEN + DELIMITER('.') + MSG_LEM
local TOKEN_LEN = SHA_LEN + 1 + DATA_LEN

--- compute
--- @param secret string
--- @param data string
--- @return string
local function compute(secret, data)
    local ctx = hmacsha(secret)
    ctx:update(data)
    return ctx:final()
end

--- verify
--- @param secret string
--- @param token string
--- @return boolean ok
local function verify(secret, token)
    if type(secret) ~= 'string' then
        error('secret must be string', 2)
    elseif type(token) ~= 'string' then
        error('token must be string', 2)
    elseif #token ~= TOKEN_LEN or sub(token, SHA_LEN + 1, SHA_LEN + 1) ~= '.' then
        return false
    end

    local data = sub(token, -DATA_LEN)
    return compute(secret, data) == sub(token, 1, SHA_LEN)
end

--- create
--- @param secret string
--- @return string str
local function create(secret)
    if type(secret) ~= 'string' then
        error('secret must be string', 2)
    end

    local data = randstr(DATA_LEN, 'urlsafe')
    return compute(secret, data) .. '.' .. data
end

return {
    create = create,
    verify = verify,
}
