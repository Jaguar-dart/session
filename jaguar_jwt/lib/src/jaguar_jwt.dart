// Copyright (c) 2016, 2019, Ravi Teja Gudapati. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

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
  ///
  /// Fills the `sub` claim in the JWT token.
  final String subject;

  /// Issuer of the token. Is optional.
  ///
  /// Authority issuing the token. This will be used during authorization to verify
  /// that expected issuer has issued the token.
  ///
  /// Fills the `iss` claim in the JWT token.
  final String issuer;

  /// List of audience that accept this token.
  ///
  /// This will be used during authorization to verify that JWT token has expected
  /// audience for the service.
  final List<String> audience;

  /// When the token was issued
  ///
  /// Fills the `iat` claim in the JWT token.
  final DateTime issuedAt;

  /// When the token becomes valid. Is optional.
  ///
  /// Fills the `nbf` claim in the JWT token.
  final DateTime notBefore;

  /// Time at which the token expires
  ///
  /// Fills `exp` claim in the JWT token.
  final DateTime expiry;

  /// Unique Id of this JWT token
  ///
  /// Fills the `jti` claim in the JWT token.
  final String jwtId;

  /// Extra payload
  ///
  /// Fills the claim with the name [payloadName] in the JWT token.
  final Map<String, dynamic> payload = new Map<String, dynamic>();

  /// Default name of the extra payload
  static const String defaultPayloadName = 'pld';

  /// Name for the extra payload claim in the JWT token
  final String payloadName;

  /// Builds claim set from individual fields
  ///
  /// The [payload] is optional. The default name of the payload claim can
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
  /// key for obtaining the payload from [data], as well as the claim name
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

/// Issues a HMAC SHA-256 signed JWT.
///
/// Creates a JWT using the [claimSet] for the payload and signing it using
/// the [hmacKey] with the HMAC SHA-256 algorithm.
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

  final encHdr = B64urlEncRFC7515.encode(json.encode(header).codeUnits);
  final encPld =
      B64urlEncRFC7515.encode(json.encode(claimSet.toJson()).codeUnits);

  final data = encHdr + '.' + encPld;

  final encSig = B64urlEncRFC7515.encode(hmac.convert(data.codeUnits).bytes);

  return data + '.' + encSig;
}

/// Verifies that signature and extracts the claim set from a JWT.
///
/// The payload in the claim set is taken from the claim whose name is
/// 'pld'. This can be changed by providing a different name for [payloadName].
///
/// Returns the decoded claim set.
///
///     final JwtClaim decClaimSet = verifyJwtHS256Signature(token, key);
///     print(decClaimSet.toJson());

JwtClaim verifyJwtHS256Signature(String token, String hmacKey,
    {String payloadName = JwtClaim.defaultPayloadName}) {
  try {
    final hmac = new Hmac(sha256, hmacKey.codeUnits);
    final List<String> parts = token.split(".");

    if (parts.length != 3) throw JwtException.invalidToken;

    // Decode header and payload

    final headerString = B64urlEncRFC7515.decodeUtf8(parts[0]);
    final payloadString = B64urlEncRFC7515.decodeUtf8(parts[1]);

    // Verify header

    final header = json.decode(headerString);
    if (header is! Map)
      throw JwtException.invalidToken; // is JSON, but not a JSON object

    if (header['typ'] != null && header['typ'] != 'JWT')
      throw JwtException.invalidToken;

    if (header['alg'] != 'HS256')
      throw JwtException.hashMismatch; // wrong algorithm

    // Verify signature: calculate signature and compare to token's signature

    final data = parts[0] + '.' + parts[1];
    final calcSig = B64urlEncRFC7515.encode(hmac.convert(data.codeUnits).bytes);

    if (calcSig != parts[2]) {
      throw JwtException.hashMismatch; // signature does not match calculated
    }

    // Convert payload into a claim set

    final payload = json.decode(payloadString);
    if (payload is! Map)
      throw JwtException.invalidToken; // is JSON, but not a JSON object

    return new JwtClaim.fromMap(payload, payloadName: payloadName);
  } on FormatException {
    // Can be caused by:
    //   - header or payload parts are not Base64url Encoding
    //   - bytes in the header or payload are not proper UTF-8
    //   - string in header or payload cannot be parsed into JSON
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

//================================================================
/// Implements "Base64url Encoding" as defined RFC 7515.
///
/// Note: the [base64Url] constant from _dart:convert_ implements "base64url"
/// from RFC 4648, which is NOT THE SAME as "Base64url Encoding" as defined by
/// RFC 7515.
///
/// Essentially, _Base64url Encoding_ is "base64url" without the padding
/// <https://tools.ietf.org/html/rfc7515#appendix-C>.

class B64urlEncRFC7515 {
  /// Encode bytes using _Base64url Encoding_.

  static String encode(List<int> octets) {
    final e = base64Url.encode(octets).replaceAll('=', ''); // padding removed

    assert(!e.contains('+')); // check it is using the URL safe alphabet
    assert(!e.contains('/')); // check it is using the URL safe alphabet

    return e;
  }

  /// Decodes a _Base64url Encoding_ string value into bytes.
  ///
  /// Throws [FormatException] if [str] is not valid Base64url Encoding.

  static List<int> decode(String encoded) {
    // Detect incorrect "base64url" or normal "base64" encoding

    if (encoded.contains('=')) {
      throw FormatException; // unexpected padding character
    }
    if (encoded.contains('+') || encoded.contains('/')) {
      throw FormatException; // unexpected character not filename safe
    }

    // Add padding, if necessary

    var output = encoded;
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
        throw FormatException; // bad length for a Base64url Encoding
    }

    // Decode

    return base64Url.decode(output); // this may throw FormatException

    /* Alternative implementation
    var output = encoded.replaceAll('-', '+').replaceAll('_', '/');
    (add padding here)
    return base64Decode(output); // this may throw FormatException
    */
  }

  /// Encodes a String into a _Base64url Encoding_ value.
  ///
  /// The [str] is encoded using UTF-8, and then those bytes are encoded using
  /// Base64url Encoding.

  static String encodeUtf8(String str) {
    return encode(utf8.encode(str));
  }

  /// Decodes a _Base64url Encoding_ value into a String.
  ///
  /// The [str] is decoded as a _Base64url Encoding_, and then those bytes
  /// are interpreted as a UTF-8 encoded string.
  ///
  /// Throws [FormatException] if it is not Base64url Encoding or does not
  /// contain a UTF-8 encoded string.

  static String decodeUtf8(String encoded) {
    return utf8.decode(decode(encoded));
  }
}
