import 'exception.dart';

/// Encodes and decodes JWT dates
class JwtDate {
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
  static DateTime? decode(dynamic? value) {
    if (value == null) {
      // Absent
      return null;
    } else if (value is int) {
      // Integer
      if (0 <= value) {
        return DateTime.fromMillisecondsSinceEpoch(value * 1000, isUtc: true);
      } else {
        throw JwtException.invalidToken; // negative
      }
    } else if (value is double) {
      // Double
      if (value.isFinite && 0.0 < value) {
        return DateTime.fromMillisecondsSinceEpoch((value * 1000).round(),
            isUtc: true);
      } else {
        throw JwtException.invalidToken; // NAN, +ve infinity or negative
      }
    } else {
      throw JwtException.invalidToken; // not an integer, nor a double
    }
  }

  /// Converts an optional DateTime to an integer NumericDate.
  ///
  /// Note: although NumericDate values can be doubles, but this implementation
  /// only returns an integer, ignoring any fractions of a second that might
  /// have been in the value. This is more portable, since non-conforming
  /// implementations might not expect non-integer values.
  static int encode(DateTime value) {
    value = value.toUtc();
    return value.millisecondsSinceEpoch ~/ 1000;
  }
}
