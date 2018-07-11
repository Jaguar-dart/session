[![Build Status](https://travis-ci.org/Jaguar-dart/jaguar_jwt.svg?branch=master)](https://travis-ci.org/Jaguar-dart/jaguar_jwt)

# jaguar_jwt

JWT utilities for Dart and Jaguar.dart

# Usage

## Issuing JWT token

```dart
  final key = 'dfsdffasdfdgdfgdfg456456456';
  final claimSet = new JwtClaim(
      subject: 'kleak',
      issuer: 'teja',
      audience: <String>['example.com', 'hello.com'],
      payload: {'k': 'v'});
  String token = issueJwtHS256(claimSet, key);
  print(token);
```

## Decoding JWT token

```dart
  final JwtClaim decClaimSet = verifyJwtHS256Signature(token, key);
  print(decClaimSet.toJson());
```

## Validating JWT token

```dart
  decClaimSet.validate(issuer: 'teja', audience: 'hello.com');
```

# Configuration

## JwtClaimSet

`JwtClaimSet` is the model to holds JWT claim set information.
To issue a JWT token, it needs:

1. `issuer`  
Authority issuing the token. This will be used during authorization to verify that expected issuer has 
issued the token.
Fills the `iss` field of the JWT token.
2. `Subject`  
Subject of the JWT token. Usually stores the user ID of the user to which the token is issued.
Fills the `sub` field of the JWT token.
3. `audience`  
List of audience that accept this token. This will be used during authorization to verify that 
JWT token has expected audience for the service.
Fills `aud` field in JWT token.
4. `expiry`  
Time at which the token expires.
Fills `exp` field in JWT token.
5. `jwtId`  
Unique identifier across services that identifies the token.
Fills `jti` field in JWT token.


