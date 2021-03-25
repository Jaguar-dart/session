// Copyright (c) 2016, Ravi Teja Gudapati. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

/// JWT support for Jaguar.dart web server
///
/// This library can be used to generate and process JSON Web Tokens (JWT).
/// For more information about JSON Web Tokens, see
/// [RFC 7519](https://tools.ietf.org/html/rfc7519).
///
/// Currently, only the HMAC SHA-256 algorithm is supported to generate/process
/// a JSON Web Signature (JWS).
///
/// To generate a JWT, create a `JwtClaim` and use [issueJwtHS256]:
///
/// ```
/// final claimSet = JwtClaim(
///      issuer: 'issuer.example.com',
///      subject: 'BD4A3FC4-9861-4171-8640-20C3004BD059',
///      audience: <String>['client1.example.com', 'client2.example.com'],
///      jwtId: _randomString(32),
///      otherClaims: <String, dynamic>{
///        'typ': 'authnresponse',
///        'pld': {'k': 'v'}
///      },
///      maxAge: const Duration(minutes: 5));
///
/// // Generate a JWT from the claim set
///
/// final token = issueJwtHS256(claimSet, sharedSecret);
/// ```
///
/// To process a JWT, use `verifyJwtHS256Signature` to verify its signature
/// and to extract a claim set from it, then verify the claim set using the
/// `JwtClaim.validate` method before using the claims from it.
///
/// ```
/// const _expectedIssuer = 'issuer.example.com';
/// const _thisClient = 'client1.example.com';
///
/// try {
///   final claimSet = verifyJwtHS256Signature(token, sharedSecret);
///
///   claimSet.validate(issuer: _expectedIssuer,  audience: _thisClient);
///
///   final tokenIdentifier = claimSet.jwtId;
///   final claimSubject = claimSet.subject;
///   if (claimSet.containsKey('typ')) {
///     final typValue = claimSet['typ'];
///     ...
///   }
///   ...
/// } on JwtException {
///    ...
/// }
/// ```
library jaguar_jwt;

export 'src/jaguar_jwt.dart';

export 'src/b64url_rfc7515.dart';
export 'src/claim.dart';
export 'src/exception.dart';
