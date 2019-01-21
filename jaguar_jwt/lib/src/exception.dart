/// JWT exception thrown when an invalid token is encountered while parsing
/// JWT token.
class JwtException implements Exception {
  /// Constant constructor for a JwtException.
  const JwtException(this.message);

  /// Exception message
  final String message;

  @override
  String toString() => message;

  /// Invalid token exception
  static const JwtException invalidToken =
      const JwtException('Invalid JWT token!');

  /// Invalid token exception
  static const JwtException headerNotJson =
      const JwtException('Invalid JWT token: Header not JSON!');

  /// Invalid token exception
  static const JwtException payloadNotJson =
      const JwtException('Invalid JWT token: Payload not JSON!');

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
