library test.validation;

import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

void main() {
  group('Validation', () {
    //================================================================

    group('Issuer', () {
      final correctIssuer = 'issuer.example.com';

      final claimSetIssuer0 = JwtClaim();
      final claimSetIssuer1 = JwtClaim(issuer: correctIssuer);

      test('Issuer does not matter', () {
        claimSetIssuer0.validate(); // no issuer parameter
        claimSetIssuer1.validate(); // no issuer parameter
      });

      test('Issuer matches', () {
        claimSetIssuer1.validate(issuer: correctIssuer);
      });

      test('Issuer mismatch', () {
        final wrongIssuer = 'wrong-isser.example.com';

        expect(() => claimSetIssuer0.validate(issuer: wrongIssuer),
            throwsA(equals(JwtException.incorrectIssuer)));

        expect(() => claimSetIssuer1.validate(issuer: wrongIssuer),
            throwsA(equals(JwtException.incorrectIssuer)));
      });
    });

    //================================================================

    group('Audience', () {
      final audience1 = 'audience1.example.com';
      final audience2 = 'audience2.example.com';
      final audience3 = 'audience3.example.com';

      final claimSetAudience0 = JwtClaim();
      final claimSetAudience1 = JwtClaim(audience: <String>[audience1]);
      final claimSetAudienceN =
          JwtClaim(audience: <String>[audience1, audience2, audience3]);

      test('Audience does not matter', () {
        claimSetAudience0.validate(); // no audience parameter
        claimSetAudience1.validate(); // no audience parameter
        claimSetAudienceN.validate(); // no audience parameter
      });

      test('Audience found', () {
        claimSetAudience1.validate(audience: audience1);

        claimSetAudienceN
          ..validate(audience: audience1)
          ..validate(audience: audience2)
          ..validate(audience: audience3);
      });

      test('Audience not found', () {
        final missingAudience = 'missing-audience.example.com';

        expect(() => claimSetAudience0.validate(audience: missingAudience),
            returnsNormally);

        expect(() => claimSetAudience1.validate(audience: missingAudience),
            throwsA(equals(JwtException.audienceNotAllowed)));

        expect(() => claimSetAudienceN.validate(audience: missingAudience),
            throwsA(equals(JwtException.audienceNotAllowed)));
      });
    });

    //================================================================

    group('Time claims', () {
      // Validation of time claims

      // Values for testing sensible time claims:
      // - notBefore can be any time, so using the time when tests are run
      // - issuedAt is 30 seconds before notBefore
      // - expiry is 60 seconds after notBefore

      //final notBefore = DateTime(2018, 12, 31, 23, 59, 59);
      final notBefore = DateTime.now();
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
        final claimSet =
            JwtClaim(issuedAt: issuedAt, notBefore: notBefore, expiry: expiry);

        test('Token constructed as expected', () {
          expect(claimSet.notBefore, isNotNull);
        });

        test('Before IssuedAt: valid', () {
          // The Issued At Claim is only used for determining how old a JWT is.
          // No validation is performed using it (other than making sure it is
          // before any Expiration Time Claim). It is valid, but weird, for a
          // JWT to claim it was issued after the current time.
          //
          // This test fails because it is before the NotBefore time.
          expect(
              () =>
                  claimSet.validate(currentTime: issuedAt.subtract(smallDelay)),
              throwsA(equals(JwtException.tokenNotYetAccepted)));
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

        final claimSet = JwtClaim(issuedAt: issuedAt, expiry: expiry);

        test('Token constructed as expected', () {
          expect(claimSet.notBefore, isNull);
        });

        test('Before IssuedAt: valid', () {
          // The Issued At Claim is only used for determining how old a JWT is.
          // No validation is performed using it (other than making sure it is
          // before any Expiration Time Claim). It is valid, but weird, for a
          // JWT to claim it was issued after the current time.
          claimSet.validate(currentTime: issuedAt.subtract(smallDelay));
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
      group('Default issuedAt and Expiry', () {
        // Claim set with no explicit time claims provided to the constructor
        final claimSet = JwtClaim();
        final whenConstructorWasInvoked = DateTime.now();

        test('Token constructed as expected', () {
          expect(claimSet.issuedAt, isNotNull); // default used
          expect(claimSet.notBefore, isNull);
          expect(claimSet.expiry, isNotNull); // default used

          expect(claimSet.issuedAt!.difference(whenConstructorWasInvoked),
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
          final weirdClaimSet = JwtClaim(
              issuedAt: issuedAt,
              notBefore: notBefore,
              expiry: notBefore.subtract(smallDelay));

          expect(weirdClaimSet.validate,
              throwsA(equals(JwtException.invalidToken)));
        });

        test('Expires at NotBefore', () {
          // Token is never valid: as soon as it becomes accepted it also expires
          final weirdClaimSet = JwtClaim(
              issuedAt: issuedAt, notBefore: notBefore, expiry: notBefore);
          expect(weirdClaimSet.validate,
              throwsA(equals(JwtException.invalidToken)));
        });

        test('Expires before Issued', () {
          // Who would issue a token that has already expired?
          final weirdClaimSet = JwtClaim(
              issuedAt: issuedAt,
              notBefore: notBefore,
              expiry: issuedAt.subtract(smallDelay));
          expect(weirdClaimSet.validate,
              throwsA(equals(JwtException.invalidToken)));
        });

        test('Expires at IssuedAt', () {
          // Who would issue a token that immediately expires?
          final weirdClaimSet = JwtClaim(
              issuedAt: issuedAt, notBefore: notBefore, expiry: issuedAt);
          expect(weirdClaimSet.validate,
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
          final readyWhenIssuedClaimSet = JwtClaim(
              subject: 'testing.notBefore-at-issuedAt',
              expiry: expiry,
              notBefore: issuedAt,
              issuedAt: issuedAt);
          expect(readyWhenIssuedClaimSet.expiry, isNotNull);
          expect(readyWhenIssuedClaimSet.notBefore, isNotNull);
          expect(readyWhenIssuedClaimSet.issuedAt, isNotNull);

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

          final readyBeforeIssuedClaimSet = JwtClaim(
              subject: 'testing.notBefore-before-issuedAt',
              expiry: expiry,
              notBefore: issuedAt.subtract(smallDelay),
              issuedAt: issuedAt);
          expect(readyBeforeIssuedClaimSet.expiry, isNotNull);
          expect(readyBeforeIssuedClaimSet.notBefore, isNotNull);
          expect(readyBeforeIssuedClaimSet.issuedAt, isNotNull);

          readyBeforeIssuedClaimSet.validate(
              currentTime: expiry.subtract(smallDelay)); // expect no exception
        });
      });
    });
  });
}
