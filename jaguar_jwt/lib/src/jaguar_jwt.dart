// Copyright (c) 2016, 2019, Ravi Teja Gudapati. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

library jaguar_jwt.src;

import 'dart:collection';
import 'dart:convert';
import 'package:crypto/crypto.dart';

//================================================================
/// JWT exception

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

//================================================================
/// Model for JwtToken
///
/// A JwtClaim represents a set of claims.
///
/// Claims are identified by a Claim Name. This implementation classifies
/// claims into two types: registered claims are those which correspond to the
/// seven _Registered Claim Names_ defined in section 4.1 of RFC 7519
/// <https://tools.ietf.org/html/rfc7519#section-4.1>; and non-registered claims
/// are all other claims.
///
/// Registered claims have their own member variable (e.g. [issuer] and [aud]).
/// Non-registered claims are accessed through the list access operator
/// (e.g. `claimSet['foo']`).
///
/// Note: a JwtClaim should be considered immutable. The claims are initialized
/// when it is created. The behaviour is undefined if a program tries to modify
/// the value of any claim (which is only possible for some cases, since most of
/// the members are final).
///
/// The `payload` getter is provided for backward compatibility with an earlier
/// release. It is deprecated. New code should handle the 'pld' claim as any
/// other non-registered claim.
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
  /// Claim Names for all the Registered Claim Names.
  ///
  /// See section 4.1 of RFC 7519 for their definition
  /// <https://tools.ietf.org/html/rfc7519#section-4.1>.

  static const registeredClaimNames = const [
    'iss',
    'sub',
    'aud',
    'exp',
    'nbf',
    'iat',
    'jti'
  ];

  // Note: when writing code, try to follow this order (which is from RFC 7519).

  /// Default duration between issued time and expiry time.
  ///
  /// Used to generate a value for Expiry when creating a claim set and no
  /// explicit value for Expiry is provided (and the generation of a default
  /// value has not been disabled).
  static const _defaultMaxAge = const Duration(days: 1);

  /// Claim Name for the legacy payload claim.
  static const String _legacyPayloadClaimName = 'pld';

  /// Issuer claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'iss'.
  final String issuer;

  /// Subject claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'sub'.
  final String subject;

  /// Audience claim
  ///
  /// If this claim does not exist, the value is an empty list.
  ///
  /// The claim name for this claim is 'aud'.
  final List<String> audience;

  /// Expiration Time claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'exp'.
  final DateTime expiry;

  /// Not Before claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'nbf'.
  final DateTime notBefore;

  /// Issued At claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'iat'.
  final DateTime issuedAt;

  /// JWT ID claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'jti'.
  final String jwtId;

  /// All non-registered claims.
  ///
  /// This is a Map where the key is the Claim Name and the value is the claim's
  /// value. The value can be anything that can be converted into JSON.
  /// For example, a scalar value (e.g. null, int or String), a List or Map.
  final _otherClaims = <String, dynamic>{};

  /// Indicates if a claim exists or not.
  ///
  /// The [claimName] can be the Claim Name of a registered claim or a
  /// non-registered claim.

  bool containsKey(String claimName) {
    if (!registeredClaimNames.contains(claimName)) {
      // Non-registered claim
      return _otherClaims.containsKey(claimName);
    } else {
      // Registered claim
      switch (claimName) {
        case 'iss':
          return issuer != null;
        case 'sub':
          return subject != null;
        case 'aud':
          return audience.isNotEmpty;
        case 'exp':
          return expiry != null;
        case 'nbf':
          return notBefore != null;
        case 'iat':
          return issuedAt != null;
        case 'jti':
          return jwtId != null;
        default:
          // coding error: all the registered claims should have been covered
          throw new UnsupportedError('bad non-registered claim: $claimName');
      }
    }
  }

  /// Retrieves the value of a claim.
  ///
  /// Pass in the Claim Name in [claimName].
  ///
  /// This method works for both registered claims and non-registered claims.
  /// For registered claims, use the corresponding member variables to retrieve
  /// their values in a type-safe manner.
  ///
  /// Returns null if the claim is not present.
  ///
  /// The value of a non-registered claim may be `null`. To distinguish between
  /// the absence of a claim and the presence of a claim whose value is null,
  /// use the [containsKey] method instead.
  ///
  /// Note: when the claim name is 'aud', null is returned when there is
  /// no audience (unlike the [audience] member, which is an empty list).

  dynamic operator [](String claimName) {
    if (!registeredClaimNames.contains(claimName)) {
      // Non-registered claim
      return _otherClaims[claimName];
    } else {
      // Registered claim
      switch (claimName) {
        case 'iss':
          return issuer;
        case 'sub':
          return subject;
        case 'aud':
          return audience.isNotEmpty ? audience : null;
        case 'exp':
          return expiry;
        case 'nbf':
          return notBefore;
        case 'iat':
          return issuedAt;
        case 'jti':
          return jwtId;
        default:
          // coding error: all the registered claims should have been covered
          throw new UnsupportedError('bad non-registered claim: $claimName');
      }
    }
  }

  /// Returns an Iterable of all the Claim Names of claims in the claim set.
  ///
  /// If [includeRegisteredClaims] is set to false, only the names of
  /// non-registered claims are returned. The default is to consider all Claim
  /// Names (i.e. for both registered and non-registered claims).

  Iterable<String> claimNames({bool includeRegisteredClaims = true}) {
    if (includeRegisteredClaims) {
      final populatedClaims = <String>[];

      for (var name in registeredClaimNames) {
        if (containsKey(name)) {
          populatedClaims.add(name); // registered claim present, include name
        }
      }

      // Include non-registered claims
      populatedClaims.addAll(_otherClaims.keys);

      return populatedClaims;
    } else {
      return _otherClaims.keys;
    }
  }

  /// The 'pld' claim.
  ///
  /// This getter is provided for backward compatibility with the previous
  /// implementation, where the "payload" is a Map of values used to populate
  /// the 'pld' claim.
  ///
  /// New code should use the list accessor operator or [containsKey] method.
  /// For example, `claimSet['pld']` to get the payload's value or
  /// `claimSet.containsKey('pld')` to check if a payload exists or not.

  @deprecated
  Map<String, dynamic> get payload {
    final pld = _otherClaims[_legacyPayloadClaimName];

    if (pld == null) {
      return {}; // No payload
    } else if (pld is Map<String, dynamic>) {
      return pld; // Has payload
    } else {
      return {}; // No payload
      // Note: legacy code only supports Map as a payload, even though new code
      // may set the 'pld' claim to other types of values.
    }
  }

  /// Constructor for a claim set.
  ///
  /// Registered claims are populated with these parameters:
  ///
  /// - [issuer] for the Issuer Claim
  /// - [subject] for the Subject Claim
  /// - [audience] for the Audience Claim (a list of zero or more Strings)
  /// - [expiry] for the Expiration Time Claim
  /// - [notBefore] for the Not Before Claim
  /// - [issuedAt] for the Issued At Claim
  /// - [jwtId] for the JWT ID Claim
  ///
  /// Non-registered claims are populated using the [otherClaims] parameter.
  /// It is a Map with the Claim Name as the key and the claim value as the
  /// value. The value must be something that can be converted into a JSON:
  /// either a scalar (i.e. null, bool, int, double or String), a List, or
  /// Map<String,dynamic>. The other claims parameter cannot be used to set
  /// registered claims.
  ///
  /// The `payload` parameter is deprecated. To include a 'pld' claim,
  /// use the [otherClaims] parameter. The use of both mechanisms at the same
  /// time (to provide two 'pld' claims) is not permitted.
  ///
  /// Normally, the Issued At Claim and Expiration Time Claim are both given
  /// default values if they are not provided.
  /// If [issuedAt] is not specified, the current time is used.
  /// If [expiry] is not specified, [maxAge] after the issuedAt time is used.
  /// This default behaviour can be disabled by setting [defauitIatExp] to
  /// false. When set to false, IssuedAt and Expiry claims are only set if they
  /// are explicitly provided.

  JwtClaim(
      {this.issuer,
      this.subject,
      List<String> audience,
      DateTime expiry,
      DateTime notBefore,
      DateTime issuedAt,
      this.jwtId,
      Map<String, dynamic> otherClaims,
      @deprecated Map<String, dynamic> payload,
      bool defaultIatExp = true,
      Duration maxAge: _defaultMaxAge})
      : audience = audience ?? [],
        issuedAt = issuedAt?.toUtc() ??
            ((defaultIatExp) ? new DateTime.now().toUtc() : null),
        notBefore = notBefore?.toUtc(),
        expiry = expiry?.toUtc() ??
            ((defaultIatExp)
                ? ((issuedAt?.toUtc() ?? new DateTime.now().toUtc())
                    .add(maxAge))
                : null) {
    // Check and record any non-registered claims

    if (otherClaims != null) {
      // Check otherClaims does not contain any registered claims.
      // Registered claims MUST be set using the specific parameter for them.
      for (var k in otherClaims.keys) {
        if (registeredClaimNames.contains(k)) {
          throw new ArgumentError.value(k, 'otherClaims',
              'registred claim not permmitted in otherClaims');
        }
      }
      _otherClaims.addAll(otherClaims);
    }

    // Treat the payload parameter as a way to provide a claim named 'pld'

    if (payload != null) {
      if (_otherClaims.containsKey(_legacyPayloadClaimName)) {
        throw new ArgumentError('do not use payload with "pld" in otherClaims');
      }
      _otherClaims[_legacyPayloadClaimName] = payload;
    }
  }

  /// Constructs a claim set from a [Map] of claims.
  ///
  /// Normally, the IssuedAt and Expiry claims are always included.
  /// If they are not present in the [data], default values are created for
  /// them. This behaviour is disabled when [defaultIatExp] is false.
  /// See the constructor's documentation for details of how [defaultIatExp]
  /// and [maxAge] is used.
  ///
  /// Throws [JwtException.invalidToken] if the Map is not suitable.

  factory JwtClaim.fromMap(Map<String, dynamic> data,
      {bool defaultIatExp = true, Duration maxAge = _defaultMaxAge}) {
    // Extract registered claims (if available) and check they are suitable

    if (data.containsKey('iss')) {
      if (data['iss'] is! String) {
        throw JwtException.invalidToken; // issuer is not a StringOrURI
      }
    }

    if (data.containsKey('sub')) {
      if (data['sub'] is! String) {
        throw JwtException.invalidToken; // subject is not a StringOrURI
      }
    }

    final audienceList = <String>[];
    if (data.containsKey('aud')) {
      // The audience claim appears in the data
      final aud = data['aud'];
      if (aud is String) {
        // Special case when the JWT has one audience
        audienceList.add(aud);
      } else if (aud is List) {
        // General case
        for (var a in aud) {
          if (a is String) {
            audienceList.add(a);
          } else {
            throw JwtException.invalidToken; // list contains a non-string value
          }
        }
      } else {
        throw JwtException.invalidToken; // unexpected type for audience

      }
    }

    final expOrNull = _numericDateDecode(data['exp']);
    final notBeforeOrNull = _numericDateDecode(data['nbf']);
    final issuedAtOrNull = _numericDateDecode(data['iat']);

    if (data.containsKey('jti')) {
      if (data['jti'] is! String) {
        throw JwtException.invalidToken; // JWT ID is not a StringOrURI
      }
    }

    // Extract all non-registered claims (including 'pld' if it is in the data)

    final others = <String, dynamic>{};

    data.forEach((k, v) {
      if (!registeredClaimNames.contains(k)) {
        others[k] = v;
      }
    });

    // Create a new JwtClaim and initialize with the registered claims

    return JwtClaim(
        issuer: data['iss'],
        subject: data['sub'],
        audience: audienceList,
        expiry: expOrNull,
        notBefore: notBeforeOrNull,
        issuedAt: issuedAtOrNull,
        jwtId: data["jti"],
        otherClaims: (others.isNotEmpty) ? others : null,
        defaultIatExp: defaultIatExp,
        maxAge: maxAge);
  }

  /// Returns Dart built-in JSON representation of JWT claim set
  Map toJson() {
    final body = <String, dynamic>{};

    // Include Registered Claim Names

    if (issuer is String) body['iss'] = issuer;
    if (subject is String) body['sub'] = subject;
    if (audience.length != 0) body['aud'] = audience;

    if (expiry != null) {
      body['exp'] = _numericDateEncode(expiry);
    }
    if (notBefore != null) {
      body['nbf'] = _numericDateEncode(notBefore);
    }
    if (issuedAt != null) {
      body['iat'] = _numericDateEncode(issuedAt);
    }

    if (jwtId is String) body['jti'] = jwtId;

    // Include non-registered claims

    _otherClaims.forEach((k, v) {
      assert(!body.containsKey(k));
      if (v is Map) {
        body[k] = _splayify(v); // Map value
      } else {
        body[k] = v; // scalar value or List
      }
    });

    // Return result

    return _splayify(body);
  }

  /// Validates the JWT claim set.
  ///
  /// Checks the for the [issuer] and [audience] and validates the Expiration
  /// Time Claim and Not Before claim, if they are present.
  ///
  /// The time claims in the token (i.e. Expiry, Not Before and Issued At) are
  /// checked with the current time.
  /// A value for [currentTime] can be provided (this is useful for validating
  /// tokens previously received/saved/created), otherwise the current time of
  /// when this method is invoked is used.
  ///
  /// For consistency, validation fails if the Expiration Time Claim is before
  /// the Not Before Claim, or the Expiration Time Claim is before the Issued At
  /// Claim.
  ///
  /// An [allowedClockSkew] can be provided to allow for differences between
  /// the clock of the system that created the token and the clock of the system
  /// doing the validation. By default, no clock skew is allowed for.

  void validate(
      {String issuer,
      String audience,
      Duration allowedClockSkew: const Duration(), // zero = allow no clock skew
      DateTime currentTime}) {
    // Ensure clock skew is never negative

    allowedClockSkew = allowedClockSkew.abs();

    // Check Issuer Claim
    if (issuer is String && this.issuer != issuer)
      throw JwtException.incorrectIssuer;

    // No checks for subject: the application is supposed to do that

    // Check Audience Claim
    if (audience is String && !this.audience.contains(audience))
      throw JwtException.audienceNotAllowed;

    // Validate time claims (if present) are consistent
    // i.e. Expiry is not Before NotBefore, and expiry is not before IssuedAt

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

    // Check Expiration Time Claim
    // Reject the token if the current time is at or after the Expiry time.
    // (At exactly Expiry is also rejected.)
    if (expiry != null && !cTime.isBefore(expiry.add(allowedClockSkew)))
      throw JwtException.tokenExpired;

    // Check Not Before Claim
    // Reject token if the current time is before the Not Before time.
    // (At exactly Not Before is ok.)
    if (notBefore != null &&
        notBefore.subtract(allowedClockSkew).isAfter(cTime))
      throw JwtException.tokenNotYetAccepted;

    // No checks for Issued At Claim
    //
    // RFC7519 only says this "can be used to determine the age of the JWT".
    //
    // Some issuers deliberately set a NotBefore time to be one minute before
    // the Issued At time. So they seem to expect NotBefore to be checked, but
    // not IssuedAt.

    // No checks for JWT ID Claim: the application is supposed to do that
  }

  //================================================================
  // Utility methods for encoding and decoding a NumericDate.
  //
  // A _NumericDate_ is how the 'iss', 'nbf' and 'exp' times are represented in
  // a JWT.
  //
  // A _NumericDate_ is specified in section 2 of RFC 7797
  // <https://tools.ietf.org/html/rfc7519#section-2> as the number of seconds
  // since 1970-01-01T00:00:00Z ignoring leap seconds.
  // Note: it could be an integer or non-integer number (i.e. doubles).
  //
  // **Leap seconds**
  //
  // Non-conformance: this implementation does not ignore leap seconds.
  // It uses the Dart DateTime value, which uses UTC or the local time of
  // the computer and should include leap seconds.
  //
  // In limited testing, it appears other implementations also simply use
  // their computer's clock. So for better interoperability, this implementation
  // does not attempt to ignore leap seconds. If this is a problem, the
  // validation of tokens can compensate for it by allowing for clock skew.
  // Alternatively, this implementation could be modified to subtract/add
  // the leap seconds when encoding/decoding a NumericDate.

  //----------------------------------------------------------------
  /// Converts an optional NumericDate into a DateTime.
  ///
  /// If the [value] is null, null is returned. Otherwise, the value (which
  /// could be an integer or double) is interpreted as a NumericDate and
  /// returned as a DateTime.
  ///
  /// If the value is a double, any milliseconds are included in the result.
  ///
  /// Throws [JwtException.invalidToken] if the value is not the correct type
  /// or is out of range.

  static DateTime _numericDateDecode(dynamic value) {
    if (value == null) {
      // Absent
      return null;
    } else if (value is int) {
      // Integer
      if (0 <= value) {
        return new DateTime.fromMillisecondsSinceEpoch(value * 1000,
            isUtc: true);
      } else {
        throw JwtException.invalidToken; // negative
      }
    } else if (value is double) {
      // Double
      if (value.isFinite && 0.0 < value) {
        return new DateTime.fromMillisecondsSinceEpoch((value * 1000).round(),
            isUtc: true);
      } else {
        throw JwtException.invalidToken; // NAN, +ve infinity or negative
      }
    } else {
      throw JwtException.invalidToken; // not an integer, nor a double
    }
  }

  //----------------------------------------------------------------
  /// Converts an optional DateTime to an integer NumericDate.
  ///
  /// Note: although NumericDate values can be doubles, but this implementation
  /// only returns an integer, ignoring any fractions of a second that might
  /// have been in the value. This is more portable, since non-conforming
  /// implementations might not expect non-integer values.

  static int _numericDateEncode(DateTime value) {
    assert(value != null);
    assert(value.isUtc); // or convert to UTC here?
    return value.millisecondsSinceEpoch ~/ 1000; // truncating division
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

  final encHdr = B64urlEncRFC7515.encodeUtf8(json.encode(header));
  final encPld = B64urlEncRFC7515.encodeUtf8(json.encode(claimSet.toJson()));

  final data = encHdr + '.' + encPld;

  final encSig = B64urlEncRFC7515.encode(hmac.convert(data.codeUnits).bytes);

  return data + '.' + encSig;
}

/// Verifies that signature and extracts the claim set from a JWT.
///
/// Returns the decoded claim set.
///
/// Normally, if IssuedAt and Expiry claims are not present, default values
/// will be generated for them and set in the the claim set that is returned.
/// This behaviour can be disabled by setting [defaultIatExp] to false.
/// See the constructor [JwtClaim] for details about what default values are
/// used.
///
///     final JwtClaim decClaimSet = verifyJwtHS256Signature(token, key);
///     print(decClaimSet.toJson());

JwtClaim verifyJwtHS256Signature(String token, String hmacKey,
    {bool defaultIatExp = true, Duration maxAge = JwtClaim._defaultMaxAge}) {
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

    // TODO: don't check the value, since "JWT" is recommended but not mandatory
    // <https://tools.ietf.org/html/rfc7519#section-5.1>
    if (header['typ'] != null && header['typ'] != 'JWT')
      throw JwtException.invalidToken;

    if (header['alg'] != 'HS256')
      throw JwtException.hashMismatch; // wrong algorithm or missing

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

    return new JwtClaim.fromMap(payload,
        defaultIatExp: defaultIatExp, maxAge: maxAge);
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
