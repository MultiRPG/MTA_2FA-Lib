# Two factor library (MTA:SA)

This is a two factor library for [Multi Theft Auto: San Andreas](https://mtasa.com/) and is designed for the usage of two factor functions.

The reason why I released this library is because I would like to take care of security on MTA servers.
Finally, I am glad to provide the 2FA library, and everyone is welcome to adjust the code and help make it better by editting the code, adding functions or events.

# Usage
Event-based OTP (also called HOTP meaning HMAC-based One-Time Password) is the original One-Time Password algorithm and relies on two pieces of information. The first is the secret key, called the "seed", which is known only by the token and the server that validates submitted OTP codes. The second piece of information is the moving factor which, in event-based OTP, is a counter. The counter is stored in the token and on the server. The counter in the token increments when the button on the token is pressed, while the counter on the server is incremented only when an OTP is successfully validated.
```lua
generateHotpCode( string secret, number counter [, string algorithm = "sha1", number digits = 6 ] )
```

Time-based OTP (TOTP for short), is based on HOTP but where the moving factor is time instead of the counter. TOTP uses time in increments called the timestep, which is usually 30 or 60 seconds. This means that each OTP is valid for the duration of the timestep.
```lua
generateTotpCode( string secret, number timestamp [, string algorithm = "sha1", number secretPeriod = 30, number digits = 6 ] )
```

The library also allows you to generate secret keys.
```lua
generateSecretKey( [ number length = 16 ] )
```

# Examples
An example of using TOTP.
```lua
local secretKey = generateSecretKey()
local totpCode = generateTotpCode( secretKey, os.time() )
outputDebugString(totpCode) -- random 6 digits
```

An example of using HOTP.
```lua
local secretKey = "JBSWY3DPEHPK3PXP"
local hotpCode = generateHotpCode( secretKey, 2137 )
outputDebugString(hotpCode) -- 064884
```

**Thanks for your support.**