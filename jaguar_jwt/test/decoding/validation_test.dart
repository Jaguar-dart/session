library test.validation;

import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

main() {
  group('Validation', () {
    //================================================================

    group('Signature', () {
      final claimSet = new JwtClaim(
          subject: 'kleak',
          issuer: 'issuer.example.com',
          audience: <String>['audience.example.com'],
          payload: {'foo': 'bar'});

      final correctSecret = 'secret';
      final wrongSecret = 'Secret'; // wrong case for first character
      String token = issueJwtHS256(claimSet, correctSecret);

      test('correct secret: verifies', () {
        expect(verifyJwtHS256Signature(token, correctSecret),
            const TypeMatcher<JwtClaim>());
      });

      test('wrong secret: fail', () {
        // Verifying with a different secret
        expect(() => verifyJwtHS256Signature(token, wrongSecret),
            throwsA(equals(JwtException.hashMismatch)));
      });

      test('tampered header: fail', () {
        // Tamper with the header so its checksum does not match the signature

        final List<String> parts = token.split(".");
        assert(parts.length == 3);

        const goodHeader = '{"alg":"HS256","typ":"JWT"}'; // control value

        // Make sure the generated JWT has the expected header, otherwise
        // tampering with the header might not produce the desired results.
        // Probably the only way the header could differ is that order of the
        // members is different (i.e. `{"typ":"JWT","alg":"HS256"}`) since
        // order is not significant in a JSON object.
        assert(B64urlEncRFC7515.decodeUtf8(parts[0]) == goodHeader,
            'assumption about generated JWT header is wrong');

        // Note: verifyJwtHS256Signature checks the header values before
        // checking the signature, so bad values in the header should produce
        // other exceptions before the signature verification fails
        // (i.e. can have other exceptions besides [JwtException.hashMismatch]).

        <String, JwtException>{
          // Different alg
          '{"typ":"JWT"}': JwtException.hashMismatch, // algorithm missing
          '{"alg":"none","typ":"JWT"}': JwtException.hashMismatch, // not HS256

          // Different typ
          '{"alg":"HS256"}': JwtException.hashMismatch, // typ missing
          '{"alg":"HS256","typ":"badValue"}': JwtException.invalidToken,
          '{"alg":"HS256","typ":"jwt"}': JwtException.invalidToken, // case diff
          '{"alg":"HS256","typ":"Jwt"}': JwtException.invalidToken, // case diff
          '{"alg":"HS256","typ":"JWt"}': JwtException.invalidToken, // case diff
          // TODO: In RFC 7519, "JWT" is only RECOMMENDED. Other values are OK.

          // Semantically same JSON, but the hash is different
          '{"typ":"JWT","alg":"HS256"}': JwtException.hashMismatch,
          '{"alg":"HS256","typ":"JWT" }': JwtException.hashMismatch,
          '{"alg":"HS256","typ":"JWT","a":"b"}': JwtException.hashMismatch,

          goodHeader: null // control
        }.forEach((header, expectedException) {
          final newHead = B64urlEncRFC7515.encodeUtf8(header);
          final tamperedToken = [newHead, parts[1], parts[2]].join('.');

          if (expectedException != null) {
            expect(() => verifyJwtHS256Signature(tamperedToken, correctSecret),
                throwsA(equals(expectedException)),
                reason: 'test failed with header=$header');
          } else {
            // Control: check the tampering code did not mess up something else
            // and the above testing were succeeding because of a different
            // cause than the one being tested.
            try {
              expect(tamperedToken, equals(token));

              expect(verifyJwtHS256Signature(tamperedToken, correctSecret),
                  const TypeMatcher<JwtClaim>(),
                  reason: 'control case failed with header=$header');
            } catch (e) {
              fail('control case failed (header=$header): threw: $e');
            }
          }
        });
      });

      //----------------------------------------------------------------

      test('tampered body: fail', () {
        // Tamper with the body so its checksum does not match the signature

        final List<String> parts = token.split(".");
        assert(parts.length == 3);

        final body = B64urlEncRFC7515.decodeUtf8(parts[1]);
        final t = body.replaceAll('"pld":{"foo":"bar"}', '"pld":{"foo":"baz"}');
        expect(t != body, isTrue, reason: 'expected substring not in payload');

        final tamperedEncoding = B64urlEncRFC7515.encodeUtf8(t);
        expect(tamperedEncoding, isNot(equals(parts[1])),
            reason: 'tampering did not modify the encoded payload');

        final tamperedToken = [parts[0], tamperedEncoding, parts[2]].join('.');
        expect(tamperedToken, isNot(equals(token)),
            reason: 'tampering did not modify the JWT');

        expect(() => verifyJwtHS256Signature(tamperedToken, correctSecret),
            throwsA(equals(JwtException.hashMismatch)),
            reason: 'unexpected result when body was tampered with');
      });

      //----------------------------------------------------------------

      test('tampered signature: fail', () {
        // Tamper with the signature

        final List<String> parts = token.split(".");
        assert(parts.length == 3);

        // Try tampering with different bits in the signature

        for (var x = 0; x < 3; x++) {
          final sigBytes = B64urlEncRFC7515.decode(parts[2]);
          switch (x) {
            case 0:
              sigBytes[0] ^= 0x80; // flip MSB of first byte
              break;
            case 1:
              sigBytes[sigBytes.length - 1] ^= 0x01; // flip LSB of last byte
              break;
            case 2:
              sigBytes[8] ^= 0x18; // flip some other bits in the signature
              break;
            default:
              assert(false);
              break;
          }

          final tamperedSig = B64urlEncRFC7515.encode(sigBytes);
          expect(tamperedSig != parts[2], isTrue); // tampering did not change

          final tamperedToken = [parts[0], parts[1], tamperedSig].join('.');

          expect(() => verifyJwtHS256Signature(tamperedToken, correctSecret),
              throwsA(equals(JwtException.hashMismatch)),
              reason:
                  'signature valid even though signature was tampered with');
        }
      });

    });

    //================================================================

    group('Issuer', () {
      final correctIssuer = 'issuer.example.com';

      final claimSetIssuer0 = new JwtClaim();
      final claimSetIssuer1 = new JwtClaim(issuer: correctIssuer);

      test('issuer does not matter: valid', () {
        claimSetIssuer0.validate(); // no issuer parameter
        claimSetIssuer1.validate(); // no issuer parameter
      });

      test('issuer matches: valid', () {
        claimSetIssuer1.validate(issuer: correctIssuer);
      });

      test('issuer mismatch: invalid', () {
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

      final claimSetAudience0 = new JwtClaim();
      final claimSetAudience1 = new JwtClaim(audience: <String>[audience1]);
      final claimSetAudienceN =
          new JwtClaim(audience: <String>[audience1, audience2, audience3]);

      test('audience does not matter: valid', () {
        claimSetAudience0.validate(); // no audience parameter
        claimSetAudience1.validate(); // no audience parameter
        claimSetAudienceN.validate(); // no audience parameter
      });

      test('audience found: valid', () {
        claimSetAudience1.validate(audience: audience1);

        claimSetAudienceN.validate(audience: audience1);
        claimSetAudienceN.validate(audience: audience2);
        claimSetAudienceN.validate(audience: audience3);
      });

      test('audience not found: invalid', () {
        final missingAudience = 'missing-audience.example.com';

        expect(() => claimSetAudience0.validate(audience: missingAudience),
            throwsA(equals(JwtException.audienceNotAllowed)));

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

      //final notBefore = new DateTime(2018, 12, 31, 23, 59, 59);
      final notBefore = new DateTime.now();
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
