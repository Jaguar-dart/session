[![Build Status](https://travis-ci.org/Jaguar-dart/jaguar_jwt.svg?branch=master)](https://travis-ci.org/Jaguar-dart/jaguar_jwt)

# jaguar_jwt

JWT utilities for Dart and Jaguar.dart

This library can be used to generate and process JSON Web Tokens (JWT).
For more information about JSON Web Tokens, see
[RFC 7519](https://tools.ietf.org/html/rfc7519).

Currently, only the HMAC SHA-256 algorithm is supported to generate/process
a JSON Web Signature (JWS).

# Usage

## Issuing a JWT

```dart
  final key = 's3cr3t';
  final claimSet = new JwtClaim(
      subject: 'kleak',
      issuer: 'teja',
      audience: <String>['audience1.example.com', 'audience2.example.com'],
      otherClaims: <String,dynamic>{
        'typ': 'authnresponse',
        'pld': {'k': 'v'}},
      maxAge: const Duration(minutes: 5));

  String token = issueJwtHS256(claimSet, key);
  print(token);
```

## Processing a JWT

To process a JWT:

1. Verify the signature and extract the claim set.
2. Validate the claim set.
3. Extract claims from the claim set.

```dart
  try {
    final JwtClaim decClaimSet = verifyJwtHS256Signature(token, key);
    // print(decClaimSet);

    decClaimSet.validate(issuer: 'teja', audience: 'audience1.example.com');

    if (claimSet.jwtId != null) {
       print(claimSet.jwtId);
    }
    if (claimSet.containsKey('typ')) {
      final v = claimSet['typ'];
      if (v is String) {
         print(v);
      } else {
        ...
      }
    }

    ...
  } on JwtException {
    ...
  }
```

# Configuration

## JwtClaimSet

`JwtClaimSet` is the model to holds JWT claim set information.

These are the registered claims:

1. `issuer`  
Authority issuing the token. This will be used during authorization to verify that expected issuer has 
issued the token.
Fills the `iss` field of the JWT.
2. `subject`  
Subject of the token. Usually stores the user ID of the user to which the token is issued.
Fills the `sub` field of the JWT.
3. `audience`  
List of audience that accept this token. This will be used during authorization to verify that 
JWT has expected audience for the service.
Fills `aud` field in JWT.
4. `expiry`  
Time when the token becomes no longer acceptable for process.
Fills `exp` field in JWT.
5. `notBefore`  
Time when the token becomes acceptable for processing.
Fills the `nbf` field in the JWT.
6. `issuedAt`  
Time when the token was issued.
Fills the `iat` field in the JWT.
7. `jwtId`  
Unique identifier across services that identifies the token.
Fills `jti` field in JWT.

Additional claims may also be included in the JWT.
