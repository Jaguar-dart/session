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

class JwtMapCoder implements MapCoder {
  final JwtConfig config;

  final JwtValidationConfig validationConfig;

  final String subjectKey;

  JwtMapCoder(this.config,
      {this.validationConfig: const JwtValidationConfig(),
      this.subjectKey: 'id'});

  /// Validates the given JWT claim set [claimSet] against [validationConfig]
  ///
  /// Must throw exception on validation failure
  void validate(JwtClaim claimSet) {
    if (validationConfig == null) return;

    try {
      claimSet.validate(
        issuer: validationConfig.issuer,
        audience: validationConfig.audience,
      );
    } catch (_) {
      throw Response(null, statusCode: HttpStatus.unauthorized);
    }
  }

  String encode(Map<String, String> values) {
    final claimSet = JwtClaim(
        issuer: config.issuer,
        subject: values[subjectKey],
        audience: config.audience,
        maxAge: config.maxAge,
        payload: values);
    return issueJwtHS256(claimSet, config.hmacKey);
  }

  Map<String, String> decode(String token) {
    final JwtClaim claimSet = verifyJwtHS256Signature(token, config.hmacKey);

    validate(claimSet);

    final ret = Map<String, String>.from(claimSet.payload);
    ret[subjectKey] = claimSet.subject;
    ret['sct'] = claimSet.issuedAt.toUtc().millisecondsSinceEpoch.toString();
    return ret;
  }
}
