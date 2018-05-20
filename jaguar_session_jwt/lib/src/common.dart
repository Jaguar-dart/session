part of jaguar_auth.session;

/// JWT config model used to issue new JWT tokens
class JwtConfig {
  /// Issuer of the token
  final String issuer;

  /// Audience in the token
  final List<String> audience;

  /// Maximum duration for which the token is valid
  final Duration maxAge;

  /// HS256 key
  final String hmacKey;

  const JwtConfig(this.hmacKey,
      {this.issuer,
      this.audience: const [],
      this.maxAge: const Duration(days: 1)});
}

/// Contains information to validate JWT claim set
class JwtValidationConfig {
  /// Issuer
  final String issuer;

  /// Audience
  final String audience;

  const JwtValidationConfig({this.issuer, this.audience});
}

abstract class _BaseJwtSession {
  JwtConfig get config;

  JwtValidationConfig get validationConfig;

  /// Validates the given JWT claim set [claimSet] against [validationConfig]
  ///
  /// Must throw exception on validation failure
  Future<Null> validate(JwtClaim claimSet) async {
    if (claimSet == null) {
      throw new Response(null, statusCode: HttpStatus.UNAUTHORIZED);
    }

    try {
      claimSet.validate(
        issuer: validationConfig.issuer,
        audience: validationConfig.audience,
      );
    } on JwtException catch (_) {
      throw new Response(null, statusCode: HttpStatus.UNAUTHORIZED);
    }
  }

  String encodeJwt(Map<String, String> values) {
    final claimSet = new JwtClaim(
        issuer: config.issuer,
        subject: values['sub'],
        audience: config.audience,
        maxAge: config.maxAge,
        payload: values);
    final String token = issueJwtHS256(claimSet, config.hmacKey);
    return const Base64Codec.urlSafe().encode(token.codeUnits);
  }

  Session decodeJwt(String data) {
    final token =
        new String.fromCharCodes(const Base64Codec.urlSafe().decode(data));
    final JwtClaim claimSet = verifyJwtHS256Signature(token, config.hmacKey);
    if (claimSet == null) return new Session.newSession({});

    final ret = new Map<String, dynamic>.from(claimSet.payload);
    ret['sub'] = claimSet.subject;
    return new Session(ret['sid'], ret, claimSet.issuedAt);
  }
}
