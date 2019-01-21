library test.encode;

import 'dart:convert';

import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

const String key = 'secret';

void main() {
  group('Encoding', () {
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

      const expectedJwt = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
          '.'
          'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
          'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
          '.'
          'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

      final issuer = 'joe';
      final exp = new DateTime.utc(2011, 03, 22, 18, 43); // 1300819380

      // Note: this secret is not a UTF-8 string
      final hmacKey = String.fromCharCodes(B64urlEncRfc7515.decode(k));

      // Create JWT

      final claimSet = new JwtClaim(
          issuer: issuer,
          expiry: exp,
          otherClaims: <String, Object>{'http://example.com/is_root': true},
          defaultIatExp: false);
      final token = issueJwtHS256(claimSet, hmacKey);

      // This simple check won't work, since the encoded header and payloads are
      // different strings, even though they both contain the same JSON object.
      // That is because the values in the RFC example contains additional
      // whitespace (newlines and spaces for indenting) and the ordering of the
      // members may be different from what jaguar_jwt produces.
      //     expect(token, equals(expectedJwt));
      // Instead, check each of the parts separately.

      // Split the JWTs into their parts

      final expectedParts = expectedJwt.split('.');
      assert(expectedParts.length == 3);

      final parts = token.split('.');
      expect(parts.length, equals(3));

      // Check header

      final expectedHeaderStr = B64urlEncRfc7515.decodeUtf8(expectedParts[0]);
      final actualHeaderStr = B64urlEncRfc7515.decodeUtf8(parts[0]);
      // print('Header produced by "jaguar_jwt": $actualHeaderStr');
      // print('Header from example in RFC 7515: $expectedHeaderStr');

      // ignore: omit_local_variable_types
      final dynamic expectedHeaderJson = json.decode(expectedHeaderStr);
      // ignore: omit_local_variable_types
      final dynamic actualHeaderJson = json.decode(actualHeaderStr);

      expect(actualHeaderJson, equals(expectedHeaderJson));

      // Check payload

      final expectedPayloadStr = B64urlEncRfc7515.decodeUtf8(expectedParts[1]);
      final actualPayloadStr = B64urlEncRfc7515.decodeUtf8(parts[1]);
      // print('Payload produced by "jaguar_jwt": $actualPayloadStr');
      // print('Payload from example in RFC 7515: $expectedPayloadStr');

      // ignore: omit_local_variable_types
      final dynamic expectedPayloadJson = json.decode(expectedPayloadStr);
      // ignore: omit_local_variable_types
      final dynamic actualPayloadJson = json.decode(actualPayloadStr);

      expect(actualPayloadJson, equals(expectedPayloadJson));

      // Signatures will be different (since other parts are different)

      expect(parts[2], isNot(equals(expectedParts[2])));
    });

    //================================================================

    group('Registered claims only', () {
      test('Registered claims only', () {
        final claimSet = new JwtClaim(
            issuer: 'teja',
            subject: '1234567890',
            audience: ['admin', 'students'],
            issuedAt: new DateTime.fromMillisecondsSinceEpoch(1481842800000,
                isUtc: true));
        final token = issueJwtHS256(claimSet, key);
        expect(
            token,
            equals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                'eyJhdWQiOlsiYWRtaW4iLCJzdHVkZW50cyJdLCJleHAiOjE0ODE5MjkyMDAsImlh'
                'dCI6MTQ4MTg0MjgwMCwiaXNzIjoidGVqYSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.'
                '3Ir0Af3-TFaC9gzgWVXvi0JJrhRzk95zFYEFmICw42k'));
      });

      test('Default iat and exp inserted', () {
        // Without defaults

        final csNoDefaults = new JwtClaim(defaultIatExp: false);
        expect(csNoDefaults.containsKey('iat'), isFalse);
        expect(csNoDefaults.issuedAt, isNull);
        expect(csNoDefaults.containsKey('exp'), isFalse);
        expect(csNoDefaults.expiry, isNull);
        expect(csNoDefaults.notBefore, isNull); // nbf is never defaulted

        // With defaults using the default maxAge

        final beforeCreation = new DateTime.now();
        final csWithDefaults = new JwtClaim();
        final afterCreation = new DateTime.now();

        expect(csWithDefaults.containsKey('iat'), isTrue);
        expect(csWithDefaults.issuedAt, const TypeMatcher<DateTime>());
        expect(csWithDefaults.containsKey('exp'), isTrue);
        expect(csWithDefaults.expiry, const TypeMatcher<DateTime>());
        expect(csNoDefaults.notBefore, isNull); // nbf is never defaulted

        expect(csWithDefaults.issuedAt.isBefore(beforeCreation), isFalse);
        expect(csWithDefaults.issuedAt.isAfter(afterCreation), isFalse);

        final defaultMaxAlive =
            csWithDefaults.expiry.difference(csWithDefaults.issuedAt);

        expect(const Duration(minutes: 1) < defaultMaxAlive, isTrue,
            reason: 'default maxAlive is too short: $defaultMaxAlive');
        expect(defaultMaxAlive < const Duration(days: 7), isTrue,
            reason: 'default maxAlive is too long: $defaultMaxAlive');
        // in jaguar_jwt 2.1.5, the actual default maxAlive is 1 day

        // With defaults and explicit maxAge

        final currentTime = new DateTime.now();
        final lifespan = const Duration(minutes: 1, seconds: 11);

        final cs = new JwtClaim(issuedAt: currentTime, maxAge: lifespan);

        // Note: issuedAt is in UTC, but currentTime is in localtime
        expect(cs.issuedAt.isAtSameMomentAs(currentTime), isTrue);
        expect(cs.expiry.isAtSameMomentAs(currentTime.add(lifespan)), isTrue);
      });
    });

    //================================================================

    group('With unregistered claims', () {
      // This group of tests demonstrates that the 'playload' and 'otherClaims'
      // parameters can both be used to create the same JWT.

      const expectedToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
          'eyJhdWQiOlsiYWRtaW4iLCJzdHVkZW50cyJdLCJleHAiOjE0ODE5MjkyMDAsImlh'
          'dCI6MTQ4MTg0MjgwMCwiaXNzIjoidGVqYSIsInBsZCI6eyJrIjoidiJ9LCJzdWIi'
          'OiIxMjM0NTY3ODkwIn0.'
          'R76R474_CwvEjkfT4WP1wL1X9PF9dp9oy5f7I3Z527U';

      test('Using payload parameter', () {
        // Create a JWT with a 'pld' claim using the legacy "payload" parameter.
        //
        // NOTE: this approach has been deprecated.

        final claimSet = new JwtClaim(
            issuer: 'teja',
            subject: '1234567890',
            audience: ['admin', 'students'],
            issuedAt: new DateTime.fromMillisecondsSinceEpoch(1481842800000,
                isUtc: true),
            payload: <String, Object>{'k': 'v'});
        final token = issueJwtHS256(claimSet, key);
        expect(token, equals(expectedToken));
      });

      test('Using otherClaims parameter', () {
        // Create a JWT with a 'pld' claim using the "otherClaims" parameter.
        // Produces exact same JWT as using the payload parameter did.

        final claimSet = new JwtClaim(
            issuer: 'teja',
            subject: '1234567890',
            audience: ['admin', 'students'],
            issuedAt: new DateTime.fromMillisecondsSinceEpoch(1481842800000,
                isUtc: true),
            otherClaims: <String, Object>{
              'pld': {'k': 'v'}
            });
        final token = issueJwtHS256(claimSet, key);
        expect(token, equals(expectedToken));
      });

      test('Different value types', () {
        const strWithSpaces = '  foo bar  BAZ  '; // multiple leading+trailing
        const strWithUnicode = '美洲虎';

        const mapValueNested = {
          'alpha': true,
          'beta': [1, 2, 3],
          'gamma': {'w': 0, 'x': 0.0, 'y': 'Zero', 'z': <Object>[]},
          'delta': [
            {'foo': 'bar'},
            {'bar': 'baz'}
          ],
          'epsilon': {
            'foo': [9, 8, 7],
            'bar': ['a', 'b', 'c']
          },
        };

        final source = new JwtClaim(
            issuer: 'issuer.example.com',
            otherClaims: <String, Object>{
              'nullValue': null,
              'boolValue0': false,
              'boolValue1': true,
              'intValueZero': 0,
              'intValuePositive': 42,
              'intValueNegative': -1,
              'doubleValueZero': 0.0,
              'doubleValuePositive': 3.14,
              'doubleValueNegative': -2.7182,
              'stringValueEmpty': '',
              'stringValueWithSpaces': strWithSpaces,
              'stringValueWithUnicode': strWithUnicode,
              'listValue': [0, 1, 2, 3],
              'mapValueEmpty': <int, bool>{},
              'mapValueMixed': {'foo': 1, 'bar': 'string'},
              'mapValueNested': mapValueNested,
            });

        final claimSet =
            verifyJwtHS256Signature(issueJwtHS256(source, key), key);

        // Claims with scalar values

        expect(claimSet['nullValue'], isNull);
        expect(claimSet['boolValue0'], equals(false));
        expect(claimSet['boolValue1'], equals(true));
        expect(claimSet['intValueZero'], equals(0));
        expect(claimSet['intValuePositive'], equals(42));
        expect(claimSet['intValueNegative'], equals(-1));
        expect(claimSet['doubleValueZero'], equals(0));
        expect(claimSet['doubleValuePositive'], equals(3.14));
        expect(claimSet['doubleValueNegative'], equals(-2.7182));
        expect(claimSet['stringValueEmpty'], equals(''));
        expect(claimSet['stringValueWithSpaces'], equals(strWithSpaces));
        expect(claimSet['stringValueWithUnicode'], equals(strWithUnicode));
        expect(claimSet['listValue'], equals([0, 1, 2, 3]));
        expect(claimSet['mapValueEmpty'], equals(<int, bool>{}));
        expect(claimSet['mapValueMixed'], equals({'bar': 'string', 'foo': 1}));
        expect(claimSet['mapValueNested'], equals(mapValueNested));

        // The list access operator cannot tell the difference between an
        // absent claim and a claim with the value of null. But the containsKey
        // method can.

        expect(claimSet['nullValue'], isNull);
        expect(claimSet['noSuchClaim'], isNull);
        expect(claimSet.containsKey('nullValue'), isTrue);
        expect(claimSet.containsKey('noSuchClaim'), isFalse);

        // The list accessor operator can be used for the registered claims too.
        // Though it is not normally used for this, since the member variables
        // provide better type safety.

        expect(claimSet['iss'], equals('issuer.example.com'));

        expect(claimSet['iat'], const TypeMatcher<DateTime>());
        expect(claimSet['exp'], const TypeMatcher<DateTime>());

        // The list accessor operator treats the audience claim differently
        // from the member when there is no audience: it returns null whereas
        // the member is an empty list.

        expect(claimSet.audience, const TypeMatcher<List<String>>());
        expect(claimSet.audience, isEmpty);
        expect(claimSet['aud'], isNull);
      });

      test('Unsuitable Claim Values', () {
        // Attempt to issue a JWT with bad Claim Values.
        // Claim Values must be suitable for representation as JSON.
        // This test ensures that non-string Map keys are detected (even if
        // they are nested deep inside Lists or other Maps) as well as other
        // reasons why the payload cannot be represented as JSON.

        final badClaimValues = [
          {42: 'non-string key in Map'},
          [
            123,
            'abc',
            {true: 'non-string key for Map inside a List'}
          ],
          {
            'mapClaimValue': {
              new DateTime(2019): 'non-string key for Map inside a Map'
            }
          },
          [
            [
              [
                [
                  {42: 'deep nesting in Lists'}
                ]
              ]
            ]
          ],
          {
            'L1': {
              'L2': {
                'L3': {
                  'L4': {42: 'deep nesting in Maps'}
                }
              }
            }
          },
          new StringBuffer('an object with no toJson() method'),
          [new StringBuffer('bad value in list')],
          {'foo': new StringBuffer('bad value as value in key/value pair')},
          {new StringBuffer('foo'): 'non-string key'}
        ];

        for (var bad in badClaimValues) {
          final cs = new JwtClaim(otherClaims: <String, Object>{'pld': bad});
          /*
          try {
            issueJwtHS256(cs, key);
          } on JsonUnsupportedObjectError catch(e) {
            print(e);
          }
          */
          expect(() => issueJwtHS256(cs, key),
              throwsA(const TypeMatcher<JsonUnsupportedObjectError>()));
        }
      });
    });
  });
}
