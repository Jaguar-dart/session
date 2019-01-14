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

    test('Incorrect.Issuer', () {
      final claimSet = new JwtClaim(
          subject: 'kleak',
          issuer: 'hello.com',
          audience: <String>['example.com', 'hello.com'],
          payload: {'k': 'v'});

      expect(() => claimSet.validate(issuer: 'whatever.com'),
          throwsA(equals(JwtException.incorrectIssuer)));
    });

    test('Incorrect.Audience', () {
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

    //----------------------------------------------------------------

    group('Time claims', () {
      // Validation of time claims

      // Values for testing sensible time claims:
      // - notBefore can be any time, so using time the tests are run
      // - issuedAt is 30 seconds before notBefore
      // - expiry is 60 seconds after notBefore

      // TODO final notBefore = new DateTime.now();
      final notBefore = new DateTime(2018, 12, 31, 17, 0, 0);
      final issuedAt = notBefore.subtract(const Duration(seconds: 30));
      final expiry = notBefore.add(const Duration(seconds: 60));

      final smallDelay = const Duration(seconds: 1);
      final bigDelay = const Duration(seconds: 11);
      final maxSkew = const Duration(seconds: 10);

      assert(smallDelay < maxSkew);
      assert(maxSkew < bigDelay);

      //----------------
      group('With NotBefore', () {
        // Claim set with all three time claims: IssuedAt, NotBefore, Expiry
        final claimSet = new JwtClaim(
            issuedAt: issuedAt, notBefore: notBefore, expiry: expiry);

        test('Token constructed as expected', () {
          expect(claimSet.notBefore, isNotNull);
        });

        test('Before IssuedAt: invalid (not yet issued)', () {
          expect(
              () =>
                  claimSet.validate(currentTime: issuedAt.subtract(smallDelay)),
              throwsA(equals(JwtException.tokenNotYetIssued)));
        });

        test('At IssuedAt: invalid (not yet accepted)', () {
          // Actually, this has nothing to do with IssuedAt, but is invalid
          // because it is before NotBefore. But the exception is different
          // from when before IssuedAt.
          expect(() => claimSet.validate(currentTime: issuedAt),
              throwsA(equals(JwtException.tokenNotYetAccepted)));
        });

        test(
            'Just After IssuedAt, but before NotBefore: invalid (not yet accepted)',
            () {
          final t = issuedAt.add(smallDelay);
          assert(t.isBefore(notBefore));
          expect(() => claimSet.validate(currentTime: t),
              throwsA(equals(JwtException.tokenNotYetAccepted)));
        });

        test('Just before NotBefore: invalid (not yet accepted)', () {
          final t = notBefore.subtract(smallDelay);
          assert(t.isBefore(notBefore));
          expect(() => claimSet.validate(currentTime: t),
              throwsA(equals(JwtException.tokenNotYetAccepted)));
        });

        test('Just before NotBefore, allowing for clock skew: valid', () {
          final t = notBefore.subtract(smallDelay);
          assert(t.isBefore(notBefore));
          claimSet.validate(currentTime: t, allowedClockSkew: maxSkew);
        });

        test('At NotBefore: valid', () {
          claimSet.validate(currentTime: notBefore); //  expect no exception
        });

        test('Just after NotBefore but before Expiry: valid', () {
          final t = notBefore.add(smallDelay);
          assert(t.isBefore(expiry));
          claimSet.validate(currentTime: t); // expect no exception
        });

        test('Just before Expires: valid', () {
          final t = expiry.subtract(smallDelay);
          claimSet.validate(currentTime: t);
        });

        test('At Expiry: invalid (expired)', () {
          expect(() => claimSet.validate(currentTime: expiry),
              throwsA(equals(JwtException.tokenExpired)));
        });

        test('At Expiry, allowing for clock skew: valid', () {
          claimSet.validate(currentTime: expiry, allowedClockSkew: maxSkew);
        });

        test('Just after Expiry: invalid (expired)', () {
          expect(() => claimSet.validate(currentTime: expiry.add(smallDelay)),
              throwsA(equals(JwtException.tokenExpired)));
        });

        test('Just after Expiry, allowing for clock skew: valid', () {
          claimSet.validate(
              currentTime: expiry.add(smallDelay), allowedClockSkew: maxSkew);
        });

        test('Way after Expiry: invalid (expired)', () {
          expect(() => claimSet.validate(currentTime: expiry.add(bigDelay)),
              throwsA(equals(JwtException.tokenExpired)));
        });

        test('Way after Expiry, allowing for clock skew: invalid (expired)',
            () {
          expect(
              () => claimSet.validate(
                  currentTime: expiry.add(bigDelay), allowedClockSkew: maxSkew),
              throwsA(equals(JwtException.tokenExpired)));
        });
      });

      //----------------
      group('Without notBefore', () {
        // Claim set with only two time claims: IssuedAt, Expiry
        //
        // Note: the JwtClaim constructor uses default values for IssuedAt
        // and Expires, if they are not provided. So it is not necessary (and
        // impossible) to test the other combinations of only two or just one
        // time claim.

        final claimSet = new JwtClaim(issuedAt: issuedAt, expiry: expiry);

        test('Token constructed as expected', () {
          expect(claimSet.notBefore, isNull);
        });

        test('Before IssuedAt: invalid (not yet issued)', () {
          expect(
              () =>
                  claimSet.validate(currentTime: issuedAt.subtract(smallDelay)),
              throwsA(equals(JwtException.tokenNotYetIssued)));
        });

        test('At IssuedAt: valid', () {
          claimSet.validate(currentTime: issuedAt);
        });

        test('Just After IssuedAt, but before Expires: valid', () {
          final t = issuedAt.add(smallDelay);
          claimSet.validate(currentTime: t);
        });

        test('Just before Expires: valid', () {
          final t = expiry.subtract(smallDelay);
          claimSet.validate(currentTime: t);
        });

        test('At Expiry: invalid (expired)', () {
          expect(() => claimSet.validate(currentTime: expiry),
              throwsA(equals(JwtException.tokenExpired)));
        });

        test('At Expiry, allowing for clock skew: valid', () {
          claimSet.validate(currentTime: expiry, allowedClockSkew: maxSkew);
        });

        test('Just after Expiry: invalid (expired)', () {
          expect(() => claimSet.validate(currentTime: expiry.add(smallDelay)),
              throwsA(equals(JwtException.tokenExpired)));
        });

        test('Just after Expiry, allowing for clock skew: valid', () {
          claimSet.validate(
              currentTime: expiry.add(smallDelay), allowedClockSkew: maxSkew);
        });

        test('Way after Expiry: invalid (expired)', () {
          expect(() => claimSet.validate(currentTime: expiry.add(bigDelay)),
              throwsA(equals(JwtException.tokenExpired)));
        });

        test('Way after Expiry, allowing for clock skew: invalid (expired)',
            () {
          expect(
              () => claimSet.validate(
                  currentTime: expiry.add(bigDelay), allowedClockSkew: maxSkew),
              throwsA(equals(JwtException.tokenExpired)));
        });
      });

      //----------------
      group('Defaults', () {
        // Claim set with no explicit time claims provided to the constructor
        final claimSet = new JwtClaim();
        final whenConstructorWasInvoked = new DateTime.now();

        test('Token constructed as expected', () {
          expect(claimSet.issuedAt, isNotNull); // default used
          expect(claimSet.notBefore, isNull);
          expect(claimSet.expiry, isNotNull); // default used

          expect(claimSet.issuedAt.difference(whenConstructorWasInvoked),
              lessThan(const Duration(seconds: 1)));
        });
      });

      //----------------
      group('Bad time claims', () {
        // The following four tests checks the validation rejects tokens
        // where the Expiry time is not sensible when compared to the IssuedAt
        // and/or NotBefore times.

        test('Expires before NotBefore', () {
          // Token is never valid
          final weirdClaimSet = new JwtClaim(
              issuedAt: issuedAt,
              notBefore: notBefore,
              expiry: notBefore.subtract(smallDelay));
          expect(() => weirdClaimSet.validate(),
              throwsA(equals(JwtException.invalidToken)));
        });

        test('Expires at NotBefore', () {
          // Token is never valid: as soon as it becomes accepted it also expires
          final weirdClaimSet = new JwtClaim(
              issuedAt: issuedAt, notBefore: notBefore, expiry: notBefore);
          expect(() => weirdClaimSet.validate(),
              throwsA(equals(JwtException.invalidToken)));
        });

        test('Expires before Issued', () {
          // Who would issue a token that has already expired?
          final weirdClaimSet = new JwtClaim(
              issuedAt: issuedAt,
              notBefore: notBefore,
              expiry: issuedAt.subtract(smallDelay));
          expect(() => weirdClaimSet.validate(),
              throwsA(equals(JwtException.invalidToken)));
        });

        test('Expires at IssuedAt', () {
          // Who would issue a token that immediately expires?
          final weirdClaimSet = new JwtClaim(
              issuedAt: issuedAt, notBefore: notBefore, expiry: issuedAt);
          expect(() => weirdClaimSet.validate(),
              throwsA(equals(JwtException.invalidToken)));
        });
      });

      //----------------
      group('Redundant time claims', () {
        // The following two tests checks the validation does not reject tokens
        // where the IssuedAt and NotBefore coincide or are in a different order
        // to the situation tested above (where NotBefore is after IssuedAt).

        test('NotBefore at IssuedAt', () {
          // The notBefore time claim is redundant, since it is the same
          // value as the IssuedAt time claim. But it is a valid claim to make.
          final readyWhenIssuedClaimSet = new JwtClaim(
              issuedAt: issuedAt, notBefore: issuedAt, expiry: expiry);
          readyWhenIssuedClaimSet.validate(
              currentTime: expiry.subtract(smallDelay)); // expect no exception
        });

        test('NotBefore before issuedAt', () {
          // This seems like a strange situation, but it might occur if the token
          // creation code is badly written. For example, claiming the token was
          // issued correctly, but hardcoded to (redundantly) claim it has been
          // valid since 1970-01-01.
          //
          // A strict implementation could reject this token, but the current
          // implementation doesn't so it can still work with those
          // "badly written" systems.

          final readyBeforeIssuedClaimSet = new JwtClaim(
              issuedAt: issuedAt,
              notBefore: issuedAt.subtract(smallDelay),
              expiry: expiry);
          readyBeforeIssuedClaimSet.validate(
              currentTime: expiry.subtract(smallDelay)); // expect no exception
        });
      });
    });
  });
}
