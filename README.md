# lua-string-token

[![test](https://github.com/mah0x211/lua-string-token/actions/workflows/test.yml/badge.svg)](https://github.com/mah0x211/lua-string-token/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/mah0x211/lua-string-token/branch/master/graph/badge.svg)](https://codecov.io/gh/mah0x211/lua-string-token)

Verifiable string token module.

## Installation

```sh
luarocks install string-token
```

## token = token.create( secret [, nbyte] )

create a token that is generated from the specified secret.  
A token is a string that is generated by the following procedure.

1. `data = random_urlsafe_string(nbyte or 32)`
2. `token = HMAC_SHA224(secret, data) .. '.' .. data`

**Parameters**

- `secret:string`: secret string.
- `nbyte:number`: the number of bytes of the random string. (default: `32`)

**Returns**

- `token:string`: token string.

**Example**

```lua
local token = require('string.token')
local t = token.create('secret')
print(t) -- 667d3a3679ef59637a558c7ded8b905c3033c46277466d0251187403.hwSCzOoAmkJR_0fnfi6T9fDZ8pTsWBtI
```


## ok = token.verify( secret, token )

verify the token string.

**Parameters**

- `secret:string`: secret string.
- `token:string`: token string.

**Returns**

- `ok: boolean`: `true` on valid token, otherwise `false`.

**Example**

```lua
local token = require('string.token')
local t = token.create('secret')
print(token.verify('secret', t)) -- true
print(token.verify('invalid', t)) -- false
```

## License

MIT
