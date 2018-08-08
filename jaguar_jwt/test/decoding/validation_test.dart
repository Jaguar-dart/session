library test.validation;

import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

main() {
  group('Validation', () {
    test('No error', () {
      final claimSet = new JwtClaim(
          subject: 'kleak',
          issuer: 'hello.com',
          audience: <String>['example.com', 'hello.com'],
          payload: {'k': 'v'});

      claimSet.validate();
      claimSet.validate(issuer: 'hello.com');
      claimSet.validate(audience: 'hello.com');
    });

    test('Invorrect.Issuer', () {
      final claimSet = new JwtClaim(
          subject: 'kleak',
          issuer: 'hello.com',
          audience: <String>['example.com', 'hello.com'],
          payload: {'k': 'v'});

      expect(() => claimSet.validate(issuer: 'whatever.com'),
          throwsA(equals(JwtException.incorrectIssuer)));
    });

    test('Invorrect.Audience', () {
      final claimSet = new JwtClaim(
          subject: 'kleak',
          issuer: 'hello.com',
          audience: <String>['example.com', 'hello.com'],
          payload: {'k': 'v'});

      expect(() => claimSet.validate(audience: 'whatever.com'),
          throwsA(equals(JwtException.audienceNotAllowed)));
    });

    test(('Signature.WithoutPadding'), () {
      String token =
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIyIiwiYWNjb3VudElkIjoiYWNjb3VudDIifQ.FEqp-uESgVJn064zwiLFUlKlOKKN1eUkFmrJtu4HOWg";
      String secret = "localdev";
      verifyJwtHS256Signature(token, secret);
    });
  });
}
