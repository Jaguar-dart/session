# jaguar_session_jwt

JWT session managers for Jaguar.

# JwtSession

JWT session manager implements `SessionManager` that stores session data in JWT format.

## Usage

Declare JwtConfig:

```dart
const jwtConfig = const JwtConfig('sdgdflgujsdgndsflkgjsdlnwertwert78676',
    issuer: 'jaguar.com');
```

Set `JwtSession` as `sessionManager` in `Jaguar`'s constructor:

```dart
main() async {
  final server = Jaguar(sessionManager: JwtSession(jwtConfig));
  // add routes here
  await server.serve();
}
```

## Configuration

`JwtSession` can be configured using `config` and `validationConfig` parameters.

`config` takes the information required to issue, sign and decode JWT tokens. Some of the important
parameters are:

`issuer`: Issuer used in `iss` field of JWT
`audience`: Audience used in `aud` field of JWT
`maxAge`: Period for which the token is valid
**`hmacKey`**: The key used to sign the JWT tokens. **Keep this key a secret.**

## Configuring transport

Use `io` to configure how session data is transported. Built-in options are:
  1. `SessionIoCookie`: Stores token in cookie
  2. `SessionIoAuthHeader`: Stores token in authorization header
  3. `SessionIoHeader`: Stores token in header

By default, `JwtSession` uses `SessionIoAuthHeader`.