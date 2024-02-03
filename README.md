Pure Nim implementation of JWT (JSON Web Token). Currently supports SHA256 and SHA512.

```nim
let secret = tokenUrlSafe(128)
# NOTE: claims
let payload = %* {
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

let token = sign(payload, secret)
echo fmt"JWT: {token}"

let isValid = verify(token, secret)
echo fmt"valid token: {isValid}"
```
