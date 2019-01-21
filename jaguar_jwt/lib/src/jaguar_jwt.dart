// Copyright (c) 2016, 2019, Ravi Teja Gudapati. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

library jaguar_jwt.src;

import 'dart:collection';
import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'b64url_rfc7515.dart';
import 'claim.dart';
import 'exception.dart';

/// Issues a HMAC SHA-256 signed JWT.
///
/// Creates a JWT using the [claimSet] for the payload and signing it using
/// the [hmacKey] with the HMAC SHA-256 algorithm.
///
/// Throws a [JsonUnsupportedObjectError] if any of the Claim Values are not
/// suitable for a JWT.
///
///     final claimSet = JwtClaim(
///       subject: 'kleak',
///       issuer: 'teja',
///       audience: <String>['example.com', 'hello.com'],
///       payload: {'k': 'v'});
///       String token = issueJwtHS256(claimSet, key);
///       print(token);
String issueJwtHS256(JwtClaim claimSet, String hmacKey) {
  final hmac = Hmac(sha256, hmacKey.codeUnits);

  // Use SplayTreeMap to ensure ordering in JSON: i.e. alg before typ.
  // Ordering is not required for JWT: it is deterministic and neater.
  final header = SplayTreeMap<String, String>.from(
      <String, String>{'alg': 'HS256', 'typ': 'JWT'});

  final String encHdr = B64urlEncRfc7515.encodeUtf8(json.encode(header));
  final String encPld =
      B64urlEncRfc7515.encodeUtf8(json.encode(claimSet.toJson()));
  final String data = '${encHdr}.${encPld}';
  final String encSig =
      B64urlEncRfc7515.encode(hmac.convert(data.codeUnits).bytes);
  return data + '.' + encSig;
}

/// Header checking function type used by [verifyJwtHS256Signature].
typedef bool JOSEHeaderCheck(Map<Object, Object> joseHeader);

/// Default JOSE Header checker.
///
/// Returns true (header is ok) if the 'typ' Header Parameter is absent, or it
/// is present with the exact value of 'JWT'. Otherwise, false (header is
/// rejected).
///
/// This implementation allows [verifyJwtHS256Signature] to exactly replicate
/// its previous behaviour.
///
/// Note: this check is more restrictive than what RFC 7519 requires, since the
/// value of 'JWT' is only a recommendation and it is supposed to be case
/// insensitive. See <https://tools.ietf.org/html/rfc7519#section-5.1>
bool defaultJWTHeaderCheck(Map<Object, Object> h) {
  if (h.containsKey('typ')) {
    final typ = h['typ'];
    if (typ is String) {
      if (typ != 'JWT') return false;
    } else {
      return false; // reject: unexpected value type for 'typ'
    }
  }
  return true; // header is ok
}

/// Verifies the signature and extracts the claim set from a JWT.
///
/// The signature is verified using the [hmacKey] with the HMAC SHA-256
/// algorithm.
///
/// The [headerCheck] is an optional function to check the header.
/// It defaults to [defaultJWTHeaderCheck].
///
/// Normally, if either the _Issued At Claim_ and/or _Expiration Time Claim_
/// are not present, default values are assigned to them.
/// This behaviour can be disabled by setting [defaultIatExp] to false.
/// See the constructor [JwtClaim] for details about what default values are
/// used and how [maxAge] is used.
///
/// Throws a [JwtException] if the signature does not verify or the
/// JWT is invalid.
///
///     final decClaimSet = verifyJwtHS256Signature(token, key);
///     print(decClaimSet);
JwtClaim verifyJwtHS256Signature(String token, String hmacKey,
    {JOSEHeaderCheck headerCheck = defaultJWTHeaderCheck,
    bool defaultIatExp = true,
    Duration maxAge = JwtClaim.defaultMaxAge}) {
  try {
    final hmac = Hmac(sha256, hmacKey.codeUnits);

    final parts = token.split('.');
    if (parts.length != 3) throw JwtException.invalidToken;

    // Decode header and payload
    final headerString = B64urlEncRfc7515.decodeUtf8(parts[0]);
    // Check header
    final Object header = json.decode(headerString);
    if (header is Map<Object, Object>) {
      // Perform any custom checks on the header
      if (headerCheck != null && !headerCheck(header)) {
        throw JwtException.invalidToken;
      }

      if (header['alg'] != 'HS256') throw JwtException.hashMismatch;
    } else {
      throw JwtException.headerNotJson;
    }

    // Verify signature: calculate signature and compare to token's signature
    final data = '${parts[0]}.${parts[1]}';
    final calcSig = B64urlEncRfc7515.encode(hmac.convert(data.codeUnits).bytes);
    // Signature does not match calculated
    if (calcSig != parts[2]) throw JwtException.hashMismatch;

    // Convert payload into a claim set
    final payloadString = B64urlEncRfc7515.decodeUtf8(parts[1]);
    final Object payload = json.decode(payloadString);
    if (payload is Map) {
      return JwtClaim.fromMap(payload,
          defaultIatExp: defaultIatExp, maxAge: maxAge);
    } else {
      throw JwtException.payloadNotJson; // is JSON, but not a JSON object
    }
  } on FormatException {
    // Can be caused by:
    //   - header or payload parts are not Base64url Encoding
    //   - bytes in the header or payload are not proper UTF-8
    //   - string in header or payload cannot be parsed into JSON
    throw JwtException.invalidToken;
  }
}
