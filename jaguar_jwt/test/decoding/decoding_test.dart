library test.decoding;

import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

final key = 'secret';

main() {
  group('Decoding', () {
    // Test JWT decoding using pre-encoded JWT values.

    const secret = 's3cr3t';

    //----------------------------------------------------------------

    test('JWS example from RFC 7515', () {
      // Example token from Appendix A.1. of "JSON Web Signature (JWS)" RFC 7515
      // <https://tools.ietf.org/html/rfc7515#appendix-A.1>
      //
      // Payload is:
      //     {"iss":"joe",
      //      "exp":1300819380,
      //      "http://example.com/is_root":true}

      final token = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
          '.'
          'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
          'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
          '.'
          'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

      final k = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
          'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

      final issuer = 'joe';
      final exp = new DateTime.utc(2011, 03, 22, 18, 43); // 1300819380

      // Note: this secret is not a UTF-8 string
      final hmacKey = String.fromCharCodes(B64urlEncRFC7515.decode(k));

      // Verify signature

      final JwtClaim claimSet = verifyJwtHS256Signature(token, hmacKey);

      // Validate the claim set

      // TODO: fix jaguar_jwt so this can validate
      // currently, it always adds "iat" of the current time when the test is
      // run, which makes this JWT non-sensible since it has an expiry time
      // before when this test is run.

      // claimSet.validate(
      //    issuer: issuer,
      //    currentTime: exp.subtract(const Duration(seconds: 60)));
    });

    //----------------------------------------------------------------

    test('no payload', () {
      // This JWT has an empty payload.

      // TThe payload is the empty string. It is not even a JSON object.
      // so while the signature validates, it cannot be converted into a claim
      // set.

      final token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..'
          'iE8S5laiOzOYJxr411Fw2HrI9I-n2F8MREyuXFwqCDo'; // empty payload part
      assert(B64urlEncRFC7515.decode(token.split('.')[1]).isEmpty); // no bytes

      // TODO: impreove error reporting so this can tell why it is invalid
      expect(() => verifyJwtHS256Signature(token, secret),
          throwsA(equals(JwtException.invalidToken)));
    });

    //----------------------------------------------------------------

    test('no claims', () {
      // This JWT has no claims in its payload.
      //
      // The payload is the string "{}", which is a JSON object with no members.
      // So there are no claims, not even 'iss', 'aud', 'iat' or 'exp'.

      final token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
          'e30.'
          'mwiDnq8rTFp5Oyy5i7pT8qktTB4tZOAfiJXTEbEqn2g';
      assert(B64urlEncRFC7515.decodeUtf8(token.split('.')[1]) == '{}');

      final claimSet = verifyJwtHS256Signature(token, secret);
      expect(claimSet.issuer, isNull);
      expect(claimSet.audience, isEmpty);
      // Values for "iat" and "exp" are added during verification, which weren't
      // in the JWT.
      expect(claimSet.jwtId, isNull);
      expect(claimSet.subject, isNull);
      expect(claimSet.payload, isEmpty);
    });

    //----------------------------------------------------------------

    // TODO: no other claims
    // TODO: basic other claims

    test('example with custom claim name', () {
      // A more complicated JWT.

      // {
      //   "iss": "https://issuer.example.com",
      //   "aud": [ "http://audience.example.com"],
      //   "iat": 1547519119,
      //   "nbf": 1547519119,
      //   "exp": 1547519239,
      //   "jti": "R4k4dsWcmS9pbpSmGHwCCeoh9RjGLfIg",
      //   "sub": "https://example.com!http://localhost:10000!000abcdefghijklmnopqrstuvwxyz",
      //   "https://aaf.edu.au/attributes": {
      //     "auedupersonsharedtoken": "ABCDEFGHIJKLMNOPQRSTUVWXYZ1",
      //     "cn": John Bigboote,
      //     "displayname": "John Bigboote",
      //     "edupersonorcid": "http://orcid.org/0000-0000-0000-0000",
      //     "edupersonprincipalname": jbigboote@example.com",
      //     "edupersonscopedaffiliation": staff@example.com",
      //     "edupersontargetedid": "https://example.com!http://localhost:10000!000abcdefghijklmnopqrstuvwxyz",
      //     "givenname": "John,
      //     "mail": "bigboote@example.com",
      //     "surname": "Bigboote"
      //     }
      // }

      final token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
          'eyJhdWQiOlsiaHR0cDovL2F1ZGllbmNlLmV4YW1wbGUuY29tIl0sImV4cCI6MTU0'
          'NzUxOTIzOSwiaHR0cHM6Ly9hYWYuZWR1LmF1L2F0dHJpYnV0ZXMiOnsiYXVlZHVw'
          'ZXJzb25zaGFyZWR0b2tlbiI6IkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMSIs'
          'ImNuIjoiSm9obiBCaWdib290ZSIsImRpc3BsYXluYW1lIjoiSm9obiBCaWdib290'
          'ZSIsImVkdXBlcnNvbm9yY2lkIjoiaHR0cDovL29yY2lkLm9yZy8wMDAwLTAwMDAt'
          'MDAwMC0wMDAwIiwiZWR1cGVyc29ucHJpbmNpcGFsbmFtZSI6ImpiaWdib290ZUBl'
          'eGFtcGxlLmNvbSIsImVkdXBlcnNvbnNjb3BlZGFmZmlsaWF0aW9uIjoic3RhZmZA'
          'ZXhhbXBsZS5jb20iLCJlZHVwZXJzb250YXJnZXRlZGlkIjoiaHR0cHM6Ly9leGFt'
          'cGxlLmNvbSFodHRwOi8vbG9jYWxob3N0OjEwMDAwITAwMGFiY2RlZmdoaWprbG1u'
          'b3BxcnN0dXZ3eHl6IiwiZ2l2ZW5uYW1lIjoiSm9obiIsIm1haWwiOiJiaWdib290'
          'ZUBleGFtcGxlLmNvbSIsInN1cm5hbWUiOiJCaWdib290ZSJ9LCJpYXQiOjE1NDc1'
          'MTkxMTksImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwianRpIjoi'
          'UjRrNGRzV2NtUzlwYnBTbUdId0NDZW9oOVJqR0xmSWciLCJuYmYiOjE1NDc1MTkx'
          'MTksInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20haHR0cDovL2xvY2FsaG9zdDox'
          'MDAwMCEwMDBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiJ9.'
          'OlCUOj66oPagFoy0MOKvg5g86ts46mY6A2WhuVhi9c0';

      final issuer = 'https://issuer.example.com';
      final audience = 'http://audience.example.com';
      final issuedAt = new DateTime.utc(2019, 1, 15, 2, 25, 19);
      final expiry = new DateTime.utc(2019, 1, 15, 2, 27, 19);
      final subject =
          'https://example.com!http://localhost:10000!000abcdefghijklmnopqrstuvwxyz';
      final jwtId = 'R4k4dsWcmS9pbpSmGHwCCeoh9RjGLfIg';

      final secret = 's3cr3t';

      // Verify the signature

      final JwtClaim claimSet = verifyJwtHS256Signature(token, secret);

      // Validate the claim set

      claimSet.validate(
          issuer: issuer,
          audience: audience,
          currentTime: issuedAt.add(const Duration(seconds: 5)));

      expect(claimSet.subject, equals(subject));
      expect(claimSet.jwtId, equals(jwtId));
    });

  });
}
