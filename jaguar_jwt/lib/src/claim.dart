import 'dart:collection';
import 'dart:convert';

import 'date.dart';
import 'exception.dart';
import 'prettify.dart';
import 'splay.dart';

/// An immutable set of claims for a Java Web Token (JWT).
///
/// A claim is represented as a name/value pair, consisting of a Claim Name
/// (which uniquely identifies the claim) and a Claim Value.
///
/// This implementation classifies
/// claims into two types: "registered claims" correspond to the
/// seven _Registered Claim Names_ defined in section 4.1 of
/// [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1); and
/// all other claims are "non-registered claims".
///
/// Registered claims have their own member variable (e.g. [issuer], [subject]
/// and [audience]).
///
/// Non-registered claims are accessed through the list access
/// [operator[]] and their presence can be determined using the
/// [containsKey] method.
///
/// The Claim Names of all present claims can be obtained using [claimNames].
///
/// Issue token from [JwtClaim]:
/// ```dart
///     final claimSet = JwtClaim(
///       subject: 'kleak',
///       issuer: 'teja',
///       audience: <String>['example.com', 'client2.example.com'],
///       otherClaims: <String,Object>{ 'pld': {'k': 'v'} });
///
///     final token = issueJwtHS256(claimSet, key);
///     print(token);
/// ```
///
/// Parse [JwtClaim] from token:
/// ```dart
///     final decClaimSet = verifyJwtHS256Signature(token, key);
///     print(decClaimSet);
/// ```
class JwtClaim {
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
  /// It is a Map with the Claim Name as the key and the Claim Value as the
  /// value. The value must be something that can be converted into a JSON:
  /// either a scalar (i.e. null, bool, int, double or String), a List, or
  /// Map<String,Object>. The otherClaims parameter cannot be used to set
  /// registered claims, only non-registered claims.
  ///
  /// To include a 'pld' claim, use the [otherClaims] parameter. The use of both
  /// mechanisms at the same time (to provide two 'pld' claims) is not permitted.
  ///
  /// Normally, the _Issued At Claim_ and _Expiration Time Claim_ are both
  /// assigned default values if they are not provided.
  /// If [issuedAt] is not specified, the current time is used.
  /// If [expiry] is not specified, [maxAge] after the _Issued At Claim_ is used.
  /// This default behaviour can be disabled by setting [defaultIatExp] to
  /// false. When set to false, the _Issued At Claim_ and and _Expiration Time
  /// Claim_ are only set if they are explicitly provided.
  JwtClaim(
      {this.issuer,
      this.subject,
      this.audience: const [],
      DateTime expiry,
      DateTime notBefore,
      DateTime issuedAt,
      this.jwtId,
      Map<String, Object> otherClaims,
      Map<String, Object> payload,
      bool defaultIatExp = true,
      Duration maxAge})
      : issuedAt = issuedAt?.toUtc() ??
            ((defaultIatExp) ? DateTime.now().toUtc() : null),
        notBefore = notBefore?.toUtc(),
        expiry = expiry?.toUtc() ??
            ((defaultIatExp)
                ? ((issuedAt?.toUtc() ?? DateTime.now().toUtc())
                    .add(maxAge ?? defaultMaxAge))
                : null) {
    // Check and record any non-registered claims
    if (otherClaims != null) {
      // Check otherClaims does not contain any registered claims.
      // Registered claims MUST be set using the specific parameter for them.
      for (String k in otherClaims.keys) {
        if (registeredClaimNames.contains(k)) {
          throw ArgumentError.value(k, 'otherClaims',
              'registred claim not permmitted in otherClaims');
        }
      }
      _otherClaims.addAll(otherClaims);
    }

    // Treat the payload parameter as a way to provide a claim named 'pld'
    if (payload != null) _otherClaims[_payloadClaimName] = payload;
  }

  /// Constructs a claim set from a Map of claims.
  ///
  /// Normally, the _Issued At_ and _Expiration Time Claims_ will always be set.
  /// If they are not present in the [data], default values are assigned to
  /// them. This behaviour is disabled when [defaultIatExp] is false.
  /// See the [JwtClaim] constructor for details of how [defaultIatExp]
  /// and [maxAge] control these default values.
  ///
  /// Throws [JwtException.invalidToken] if the Map is not suitable.
  factory JwtClaim.fromMap(Map<Object, Object> data,
      {bool defaultIatExp = true, Duration maxAge}) {
    final singleStringValue = <String, String>{};
    for (var claimName in ['iss', 'sub', 'jti']) {
      if (data.containsKey(claimName)) {
        final v = data[claimName];
        if (v is String) {
          singleStringValue[claimName] = v;
        } else {
          throw JwtException.invalidToken; // claim is not a StringOrURI
        }
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

    final expOrNull = JwtDate.decode(data['exp']);
    final notBeforeOrNull = JwtDate.decode(data['nbf']);
    final issuedAtOrNull = JwtDate.decode(data['iat']);

    // Extract all non-registered claims (including 'pld' if it is in the data)
    final others = <String, Object>{};
    data.forEach((k, v) {
      if (k is String) {
        if (!registeredClaimNames.contains(k)) {
          others[k] = v;
        }
      } else {
        throw JwtException.invalidToken; // Map had non-String as a key
      }
    });

    // Create a new JwtClaim and initialize with the registered claims
    return JwtClaim(
        issuer: singleStringValue['iss'],
        subject: singleStringValue['sub'],
        audience: audienceList,
        expiry: expOrNull,
        notBefore: notBeforeOrNull,
        issuedAt: issuedAtOrNull,
        jwtId: singleStringValue['jti'],
        otherClaims: (others.isNotEmpty) ? others : null,
        defaultIatExp: defaultIatExp,
        maxAge: maxAge);
  }

  /// Issuer Claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'iss'.
  final String issuer;

  /// Subject Claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'sub'.
  final String subject;

  /// Audience Claim
  ///
  /// If this claim does not exist, the value is an empty list.
  ///
  /// The claim name for this claim is 'aud'.
  final List<String> audience;

  /// Expiration Time Claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'exp'.
  final DateTime expiry;

  /// Not Before Claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'nbf'.
  final DateTime notBefore;

  /// Issued At Claim
  ///
  /// If this claim does not exist, the value is null.
  ///
  /// The claim name for this claim is 'iat'.
  final DateTime issuedAt;

  /// JWT ID Claim
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
  final _otherClaims = <String, Object>{};

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
          throw UnsupportedError('bad non-registered claim: $claimName');
      }
    }
  }

  /// Retrieves the value of a claim.
  ///
  /// The [claimName] can be the Claim Name for either registered claims or
  /// non-registered claims. But for registered claims, for type-safety, it
  /// may be better to use its corresponding member variables.
  ///
  /// Returns null if the claim is not present or the Claim Value is the
  /// null value. Use the [containsKey] method to distinguish between
  /// the absence of a claim and the presence of a claim whose value is null.
  ///
  /// Note: when the claim name is 'aud', this method returns null when there is
  /// no Audience Claim (unlike the [audience] member variable, which will be an
  /// empty list).
  Object operator [](String claimName) {
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
          throw UnsupportedError('bad non-registered claim: $claimName');
      }
    }
  }

  /// Returns an Iterable of all the Claim Names of claims in the claim set.
  ///
  /// The default is to consider all Claim Names (i.e. for both registered and
  /// non-registered claims). If [includeRegisteredClaims] is set to false,
  /// registered claims are not included.
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

  /// The payload (pld) claim.
  Map<String, Object> get payload {
    final pld = _otherClaims[_payloadClaimName];

    if (pld is Map<String, Object> || pld == null)
      return pld as Map<String, Object>;

    throw Exception('Invalid payload type found in the JWT token!');
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
  /// To ensure the claim set is sensible, validation will fail if the
  /// _Expiration Time Claim_ is before the _Not Before Claim_, or the
  /// _Expiration Time Claim_ is before the _Issued At Claim_.
  ///
  /// An [allowedClockSkew] can be provided to allow for differences between
  /// the clock of the system that created the token and the clock of the system
  /// doing the validation. By default, there is no allowance for clock skew
  /// (i.e. it defaults to a duration of zero).
  void validate(
      {String issuer,
      String audience,
      Duration allowedClockSkew,
      DateTime currentTime}) {
    // Ensure clock skew has a value and is never negative
    final absClockSkew = allowedClockSkew?.abs() ?? const Duration();

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
    final cTime = (currentTime ?? DateTime.now()).toUtc();

    // Check Expiration Time Claim
    // Reject the token if the current time is at or after the Expiry time.
    // (At exactly Expiry is also rejected.)
    if (expiry != null && !cTime.isBefore(expiry.add(absClockSkew)))
      throw JwtException.tokenExpired;

    // Check Not Before Claim
    // Reject token if the current time is before the Not Before time.
    // (At exactly Not Before is ok.)
    if (notBefore != null && notBefore.subtract(absClockSkew).isAfter(cTime))
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

  /// Converts the claim set into a Map suitable for encoding as JSON.
  Map toJson() {
    final body = SplayTreeMap<String, Object>();

    // Registered claims
    if (issuer is String) body['iss'] = issuer;
    if (subject is String) body['sub'] = subject;
    if (audience.isNotEmpty) body['aud'] = audience;
    if (expiry != null) body['exp'] = JwtDate.encode(expiry);
    if (notBefore != null) body['nbf'] = JwtDate.encode(notBefore);
    if (issuedAt != null) body['iat'] = JwtDate.encode(issuedAt);
    if (jwtId is String) body['jti'] = jwtId;

    // Non-registered claims
    _otherClaims.forEach((k, v) {
      assert(!body.containsKey(k));
      try {
        body[k] = splay(v);
      } on FormatException catch (e) {
        throw JsonUnsupportedObjectError('JWT claim: $k (${e.message})');
      }
    });

    // Return result (SplayTreeMap means JSON has the keys in sorted order)

    return body;
  }

  /// Converts a JwtClaim into a multi-line String for display.
  @override
  String toString() => prettify(this);

  /// Claim Names for all the Registered Claim Names.
  ///
  /// For their defintion, see section 4.1 of
  /// [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1).
  static const List<String> registeredClaimNames = const [
    'iss',
    'sub',
    'aud',
    'exp',
    'nbf',
    'iat',
    'jti'
  ];

  /// Default duration between issued time and expiry time.
  ///
  /// Used to generate a value for Expiry when creating a claim set and no
  /// explicit value for Expiry is provided (and the generation of a default
  /// value has not been disabled).
  static const defaultMaxAge = const Duration(days: 1);

  /// Claim Name for the legacy payload claim.
  static const String _payloadClaimName = 'pld';
}
