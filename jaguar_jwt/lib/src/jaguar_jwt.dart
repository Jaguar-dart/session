// Copyright (c) 2016, Ravi Teja Gudapati. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library jaguar_jwt.src;

import 'dart:collection';
import 'dart:convert';
import 'package:crypto/crypto.dart';

/// Jwt exception
class JwtException {
  /// Exception message
  final String message;

  const JwtException(this.message);

  String toString() => message;

  /// Invalid token exception
  static const JwtException invalidToken =
      const JwtException('Invalid JWT token!');

  /// Hash mismatch exception
  static const JwtException hashMismatch =
      const JwtException('JWT hash mismatch!');

  /// Token Expired time reached exception
  static const JwtException tokenExpired =
      const JwtException('JWT token expired!');

  /// Token Not Before time not yet reached exception
  static const JwtException tokenNotYetAccepted =
      const JwtException('JWT token not yet accepted!');

  /// Token Issued At time not yet reached exception
  static const JwtException tokenNotYetIssued =
      const JwtException('JWT token not yet issued!');

  /// Unallowed audience
  static const JwtException audienceNotAllowed =
      const JwtException('Audience not allowed!');

  /// Incorrect issuer
  static const JwtException incorrectIssuer =
      const JwtException('Incorrect issuer!');
}

/// Model for JwtToken
///
/// Issue token from [JwtClaim]:
///     final claimSet = new JwtClaim(
///       subject: 'kleak',
///       issuer: 'teja',
///       audience: <String>['example.com', 'hello.com'],
///       payload: {'k': 'v'});
///       String token = issueJwtHS256(claimSet, key);
///       print(token);
///
/// Parse [JwtClaim] from token:
///     final JwtClaim decClaimSet = verifyJwtHS256Signature(token, key);
///     print(decClaimSet.toJson());
class JwtClaim {
  /// Subject to which the token is issued
  final String subject;

  /// Issuer of the token. Is optional.
  ///
  /// Authority issuing the token. This will be used during authorization to verify
  /// that expected issuer has issued the token.
  /// Fills the `iss` field of the JWT token.
  final String issuer;

  /// List of audience that accept this token.
  ///
  /// This will be used during authorization to verify that JWT token has expected
  /// audience for the service.
  final List<String> audience;

  /// When the token was issued
  final DateTime issuedAt;

  /// When the token becomes valid (optional: null if not set)
  final DateTime notBefore;

  /// Time at which the token expires
  /// Fills `exp` field in JWT token
  final DateTime expiry;

  /// Unique Id of this JWT token
  final String jwtId;

  /// Extra payload
  final Map<String, dynamic> payload = new Map<String, dynamic>();

  /// Default name of the extra payload
  static const String defaultPayloadName = 'pld';

  /// Name for the extra payload
  final String payloadName;

  /// Builds claim set from individual fields
  ///
  /// The [payload] is optional. The default name of the payload member can
  /// be overridden by providing a [payloadName].
  ///
  /// Note: the Issued At and Expiry time claims are always populated.
  /// If [issuedAt] is not specified, the current time is used.
  /// If [expiry] is not specified, [maxAge] after the issuedAt time is used.
  /// If [notBefore] is not specified, is is not included in the claim.
  JwtClaim(
      {this.subject,
      this.issuer,
      DateTime expiry,
      Duration maxAge: const Duration(days: 1),
      List<String> audience,
      DateTime issuedAt,
      DateTime notBefore,
      this.jwtId,
      this.payloadName = defaultPayloadName,
      Map<String, dynamic> payload})
      : issuedAt = issuedAt?.toUtc() ?? new DateTime.now().toUtc(),
        notBefore = notBefore?.toUtc(),
        expiry = expiry?.toUtc() ??
            (issuedAt?.toUtc() ?? new DateTime.now().toUtc()).add(maxAge),
        audience = audience ?? [] {
    if (payload is Map) this.payload.addAll(payload);
  }

  /// Builds claim set from [Map]
  ///
  /// The [payloadName] is used as the extra payload's name. It is used as the
  /// key for obtaining the payload from [data], as well as the member name
  /// in the claim set that is produced.
  ///
  /// If not provided, it defaults to [defaultPayloadName].
  factory JwtClaim.fromMap(Map data,
      {String payloadName = defaultPayloadName}) {
    final DateTime exp = data["exp"] is int
        ? new DateTime.fromMillisecondsSinceEpoch(data["exp"] * 1000,
            isUtc: true)
        : null;
    final DateTime notBefore = data["nbf"] is int
        ? new DateTime.fromMillisecondsSinceEpoch(data["nbf"] * 1000,
            isUtc: true)
        : null;
    final DateTime issuedAt = data["iat"] is int
        ? new DateTime.fromMillisecondsSinceEpoch(data["iat"] * 1000,
            isUtc: true)
        : null;
    return new JwtClaim(
      subject: data['sub'],
      issuer: data['iss'],
      audience: (data["aud"] as List)?.cast<String>(),
      issuedAt: issuedAt,
      notBefore: notBefore,
      payloadName: payloadName,
      payload: data[payloadName],
      jwtId: data["jti"],
      expiry: exp,
    );
  }

  /// Returns Dart built-in JSON representation of JWT claim set
  Map toJson() {
    final body = <String, dynamic>{
      "exp": expiry.millisecondsSinceEpoch ~/ 1000,
      "iat": issuedAt.millisecondsSinceEpoch ~/ 1000,
    };

    // Add optional fields

    if (issuer is String) body['iss'] = issuer;
    if (subject is String) body['sub'] = subject;
    if (audience.length != 0) body['aud'] = audience;
    if (payload.length != 0) body[payloadName] = _splayify(payload);
    if (jwtId is String) body['jti'] = jwtId;
    if (notBefore != null) {
      body['nbf'] = notBefore.millisecondsSinceEpoch ~/ 1000;
    }

    return _splayify(body);
  }

  /// Validates the JWT claim set against provided [issuer] and [audience]
  /// Also checks that the claim set hasn't expired
  ///
  /// The time claims in the token (i.e. Expiry, Not Before and Issued At) are
  /// checked with the current time.
  /// A value for [currentTime] can be provided (this is useful for validating
  /// tokens previously received/saved/created), otherwise the current time of
  /// when this method is invoked is used.
  ///
  /// An [allowedClockSkew] can be provided to allow for differences between
  /// the clock of the system that created the token and the clock of the system
  /// doing the validation. By default, no clock skew is allowed for.

  void validate(
      {String issuer,
      String audience,
      Duration allowedClockSkew: const Duration(),
      DateTime currentTime}) {
    // Ensure clock skew is never negative

    allowedClockSkew = allowedClockSkew.abs();

    // Validate time claims are consistent

    if (expiry != null && notBefore != null && !expiry.isAfter(notBefore))
      throw JwtException.invalidToken;

    if (expiry != null && issuedAt != null && !expiry.isAfter(issuedAt))
      throw JwtException.invalidToken;

    // Validate time claims against the current time
    //
    // This implementation only checks a time claim if it is present in the
    // token (they are all optional according to RFC 7519).
    // Note: the current constructor always ensures the issuedAt and Expires
    // time claims are always populated (even when it is created from an encoded
    // token that didn't have them).

    final cTime = (currentTime ?? new DateTime.now()).toUtc();

    // Check Issued At
    // RFC7519 does not describe if or how the Issued At time claim is checked.
    // This implementation rejects the token if the current time is before token
    // was issued.
    if (issuedAt != null && cTime.isBefore(issuedAt.subtract(allowedClockSkew)))
      throw JwtException.tokenNotYetIssued;

    // Check Not Before
    // Reject token if the current time is before the Not Before time.
    if (notBefore != null &&
        notBefore.subtract(allowedClockSkew).isAfter(cTime))
      throw JwtException.tokenNotYetAccepted;

    // Check expiry
    // Reject the token if the current time is at or after the Expiry time.
    if (expiry != null && !cTime.isBefore(expiry.add(allowedClockSkew)))
      throw JwtException.tokenExpired;

    // Validate other claims

    // Check audience
    if (audience is String && !this.audience.contains(audience))
      throw JwtException.audienceNotAllowed;

    // Check issuer
    if (issuer is String && this.issuer != issuer)
      throw JwtException.incorrectIssuer;
  }
}

/// Issues a HS256 based JWT token from given claim set
///
///     final claimSet = new JwtClaim(
///       subject: 'kleak',
///       issuer: 'teja',
///       audience: <String>['example.com', 'hello.com'],
///       payload: {'k': 'v'});
///       String token = issueJwtHS256(claimSet, key);
///       print(token);
String issueJwtHS256(JwtClaim claimSet, String hmacKey) {
  final hmac = new Hmac(sha256, hmacKey.codeUnits);
  final SplayTreeMap<String, String> header =
      new SplayTreeMap.from({"alg": "HS256", "typ": "JWT"});
  final String headerString = base64UrlEncode(json.encode(header).codeUnits);
  final String payloadString =
      base64UrlEncode(json.encode(claimSet.toJson()).codeUnits);
  final String data = headerString + "." + payloadString;
  final List<int> signature = hmac.convert(data.codeUnits).bytes;
  return data + "." + base64UrlEncode(signature);
}

/// Verifies that JWT token is has correct signature.
///
/// The payload in the claim set is taken from the JSON member whose name is
/// 'pld'. This can be changed by providing a different name for [payloadName].
///
/// Returns the decoded claim set.
///
///     final JwtClaim decClaimSet = verifyJwtHS256Signature(token, key);
///     print(decClaimSet.toJson());
JwtClaim verifyJwtHS256Signature(String token, String hmacKey,
    {String payloadName = JwtClaim.defaultPayloadName}) {
  final hmac = new Hmac(sha256, hmacKey.codeUnits);
  final List<String> parts = token.split(".");

  if (parts.length != 3) throw JwtException.invalidToken;

  {
    try {
      final String headerString = _decodeBase64(parts[0]);
      final map = json.decode(headerString);
      if (map is! Map) throw JwtException.invalidToken;
      if (map['typ'] != null && map['typ'] != 'JWT')
        throw JwtException.invalidToken;
      if (map['alg'] != 'HS256') throw JwtException.hashMismatch;
    } on FormatException catch (_) {
      throw JwtException.invalidToken;
    }
  }

  final String payloadString = _decodeBase64(parts[1]);
  final String data = parts[0] + "." + parts[1];
  String signature = base64UrlEncode(hmac.convert(data.codeUnits).bytes);

  if (signature != parts[2]) {
    signature = signature.substring(0, signature.indexOf('='));
    if (signature != parts[2]) throw JwtException.hashMismatch;
  }

  try {
    final map = json.decode(payloadString);
    if (map is! Map) throw JwtException.invalidToken;

    return new JwtClaim.fromMap(map, payloadName: payloadName);
  } on FormatException catch (_) {
    throw JwtException.invalidToken;
  }
}

SplayTreeMap _splayify(Map map) {
  var data = {};
  map.forEach((k, v) {
    data[k] = _splay(v);
  });
  return new SplayTreeMap.from(data);
}

_splay(value) {
  if (value is Iterable) {
    return value.map(_splay).toList();
  } else if (value is Map)
    return _splayify(value);
  else
    return value;
}

/// Calls [base64Decode], but also works for strings with lengths
/// that are *not* multiples of 4.
String _decodeBase64(String str) {
  String output = str.replaceAll('-', '+').replaceAll('_', '/');

  switch (output.length % 4) {
    case 0:
      break;
    case 2:
      output += '==';
      break;
    case 3:
      output += '=';
      break;
    default:
      throw 'Illegal base64url string!"';
  }

  return utf8.decode(base64Decode(output));
}
