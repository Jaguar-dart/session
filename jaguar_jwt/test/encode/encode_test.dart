library test.encode;

import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

final key = 'secret';

main() {
  group('Encoding', () {

    /*
    test('JWS example from RFC 7515', () {
      // Example token from Appendix A.1. of "JSON Web Signature (JWS)" RFC 7515
      // <https://tools.ietf.org/html/rfc7515#appendix-A.1>
      //
      // Payload is:
      //     {"iss":"joe",
      //      "exp":1300819380,
      //      "http://example.com/is_root":true}

      final k = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
          'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

      final issuer = 'joe';
      final exp = new DateTime.utc(2011, 03, 22, 18, 43); // 1300819380

      // Note: this secret is not a UTF-8 string
      final hmacKey = String.fromCharCodes(B64urlEncRFC7515.decode(k));

      // Create JWT

      final claimSet = new JwtClaim(issuer: issuer, expiry: exp);
      final token = issueJwtHS256(claimSet, key);

      // TODO: jaguar_jwt currently cannot replicate this JWT
      // since it always adds 'iat' and 'exp' claims.
      expect(
          token,
          equals('eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
              '.'
              'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
              'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
              '.'
              'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
    });
    */

    test('Nopayload', () {
      final claimSet = new JwtClaim(
          issuer: 'teja',
          subject: '1234567890',
          audience: ["admin", "students"],
          issuedAt: new DateTime.fromMillisecondsSinceEpoch(1481842800000,
              isUtc: true));
      String token = issueJwtHS256(claimSet, key);
      expect(
          token,
          equals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
              'eyJhdWQiOlsiYWRtaW4iLCJzdHVkZW50cyJdLCJleHAiOjE0ODE5MjkyMDAsImlh'
              'dCI6MTQ4MTg0MjgwMCwiaXNzIjoidGVqYSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.'
              '3Ir0Af3-TFaC9gzgWVXvi0JJrhRzk95zFYEFmICw42k'));
    });

    test('With payload: default name (pld)', () {
      final claimSet = new JwtClaim(
          issuer: 'teja',
          subject: '1234567890',
          audience: ["admin", "students"],
          issuedAt: new DateTime.fromMillisecondsSinceEpoch(1481842800000,
              isUtc: true),
          payload: {"k": "v"});
      String token = issueJwtHS256(claimSet, key);
      expect(
          token,
          equals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
              'eyJhdWQiOlsiYWRtaW4iLCJzdHVkZW50cyJdLCJleHAiOjE0ODE5MjkyMDAsImlh'
              'dCI6MTQ4MTg0MjgwMCwiaXNzIjoidGVqYSIsInBsZCI6eyJrIjoidiJ9LCJzdWIi'
              'OiIxMjM0NTY3ODkwIn0.'
              'R76R474_CwvEjkfT4WP1wL1X9PF9dp9oy5f7I3Z527U'));
    });

    test('With payload: custom name', () {
      final claimSet = new JwtClaim(
          issuer: 'teja',
          subject: '1234567890',
          audience: ["admin", "students"],
          issuedAt: new DateTime.fromMillisecondsSinceEpoch(1481842800000,
              isUtc: true),
          payloadName: 'customPayload',
          payload: {"k": "v"});
      String token = issueJwtHS256(claimSet, key);
      expect(
          token,
          equals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
              'eyJhdWQiOlsiYWRtaW4iLCJzdHVkZW50cyJdLCJjdXN0b21QYXlsb2FkIjp7Imsi'
              'OiJ2In0sImV4cCI6MTQ4MTkyOTIwMCwiaWF0IjoxNDgxODQyODAwLCJpc3MiOiJ0'
              'ZWphIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.'
              'Hdu7W1AA1Ksubm5Bs9ra-DYE3UH62t6e5cjJ5zp7bzo'));
    });
  });
}
