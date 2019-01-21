import 'dart:convert';

/// Implements "Base64url Encoding" as defined RFC 7515.
///
/// Note: the `base64Url` constant from _dart:convert_ implements "base64url"
/// from RFC 4648, which is different from the "Base64url Encoding" defined by
/// RFC 7515.
///
/// Essentially, _Base64url Encoding_ is "base64url" without any padding
/// characters. For more information, see Appendix C of
/// [RFC 7515](https://tools.ietf.org/html/rfc7515#appendix-C).
class B64urlEncRfc7515 {
  B64urlEncRfc7515._preventDefaultConstructor();

  /// Encodes a sequence of bytes using _Base64url Encoding_.
  static String encode(List<int> octets) =>
      base64Url.encode(octets).replaceAll('=', ''); // padding removed

  /// Decodes a _Base64url Encoding_ string value into a sequence of bytes.
  ///
  /// Throws [FormatException] if the [encoded] string is not valid
  /// Base64url Encoding.
  static List<int> decode(String encoded) {
    // Detect incorrect "base64url" or normal "base64" encoding
    if (encoded.contains('=')) {
      throw const FormatException('Base64url Encoding: padding not allowed');
    }
    if (encoded.contains('+') || encoded.contains('/')) {
      throw const FormatException('Base64url Encoding: + and / not allowed');
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
        throw const FormatException('Base64url Encoding: invalid length');
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
  /// The [str] is encoded using UTF-8, and then that sequence of bytes are
  /// encoded using _Base64url Encoding_.
  static String encodeUtf8(String str) => encode(utf8.encode(str));

  /// Decodes a _Base64url Encoding_ value into a String.
  ///
  /// The [encoded] string is decoded as a _Base64url Encoding_, and then those
  /// sequence of bytes are interpreted as a UTF-8 encoded string.
  ///
  /// Throws [FormatException] if it is not Base64url Encoding or does not
  /// contain a UTF-8 encoded string.
  static String decodeUtf8(String encoded) => utf8.decode(decode(encoded));
}
