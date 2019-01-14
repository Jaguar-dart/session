library test.decoding;

import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

final key = 'secret';

main() {
  group('Decoding', () {
    test('Nopayload', () {
      final String token =
          r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYWRtaW4iLCJzdHVkZW50cyJdLCJleHAiOjE0ODE5MjkyMDAsImlhdCI6MTQ4MTg0MjgwMCwiaXNzIjoidGVqYSIsInN1YiI6IjEyMzQ1Njc4OTAifQ==.sbsys3_L_Yc_L8S8KsiX3cBtQp34-jbX_eWhm6O8lxY=';

      final JwtClaim claimSet = verifyJwtHS256Signature(token, key);

      expect(claimSet.issuer, equals('teja'));
      expect(claimSet.subject, "1234567890");
      expect(claimSet.audience, equals(["admin", "students"]));
      expect(claimSet.payload, isEmpty);
      expect(claimSet.issuedAt,
          new DateTime.fromMillisecondsSinceEpoch(1481842800000, isUtc: true));
      expect(
          claimSet.expiry,
          new DateTime.fromMillisecondsSinceEpoch(1481842800000, isUtc: true)
              .add(new Duration(days: 1)));
    });

    test('With payload: default name (pld)', () {
      String token =
          r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYWRtaW4iLCJzdHVkZW50cyJdLCJleHAiOjE0ODE5MjkyMDAsImlhdCI6MTQ4MTg0MjgwMCwiaXNzIjoidGVqYSIsInBsZCI6eyJrIjoidiJ9LCJzdWIiOiIxMjM0NTY3ODkwIn0=.8C3WCOzfgAGvO7niu31HrkS_m883Vp8MSs7RMr9gN6g=';
      final JwtClaim claimSet = verifyJwtHS256Signature(token, key);
      expect(claimSet.issuer, equals('teja'));
      expect(claimSet.audience, equals(["admin", "students"]));
      expect(claimSet.payload, equals({"k": "v"}));
      expect(claimSet.subject, "1234567890");
      expect(claimSet.issuedAt,
          new DateTime.fromMillisecondsSinceEpoch(1481842800000, isUtc: true));
      expect(
          claimSet.expiry,
          new DateTime.fromMillisecondsSinceEpoch(1481842800000, isUtc: true)
              .add(new Duration(days: 1)));
    });

    test('With payload: custom name', () {
      String token =
          r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYWRtaW4iLCJzdHVkZW50cyJdLCJjdXN0b21QYXlsb2FkIjp7ImsiOiJ2In0sImV4cCI6MTQ4MTkyOTIwMCwiaWF0IjoxNDgxODQyODAwLCJpc3MiOiJ0ZWphIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.Hdu7W1AA1Ksubm5Bs9ra-DYE3UH62t6e5cjJ5zp7bzo=';
      final JwtClaim claimSet =
          verifyJwtHS256Signature(token, key, payloadName: 'customPayload');
      expect(claimSet.issuer, equals('teja'));
      expect(claimSet.audience, equals(["admin", "students"]));
      expect(claimSet.payload, equals({"k": "v"}));
      expect(claimSet.subject, "1234567890");
      expect(claimSet.issuedAt,
          new DateTime.fromMillisecondsSinceEpoch(1481842800000, isUtc: true));
      expect(
          claimSet.expiry,
          new DateTime.fromMillisecondsSinceEpoch(1481842800000, isUtc: true)
              .add(new Duration(days: 1)));
    });
  });
}
