import 'dart:math';

import 'package:jaguar_jwt/jaguar_jwt.dart';

const String sharedSecret = 's3cr3t';

void main() {
  final jwt = senderCreatesJwt();
  receiverProcessesJwt(jwt);
}

String senderCreatesJwt() {
  // Create a claim set

  final claimSet = new JwtClaim(
      issuer: 'teja',
      subject: 'kleak',
      audience: <String>['client1.example.com', 'client2.example.com'],
      jwtId: _randomString(32),
      otherClaims: <String, dynamic>{
        'typ': 'authnresponse',
        'pld': {'k': 'v'}
      },
      maxAge: const Duration(minutes: 5));

  // Generate a JWT from the claim set

  final token = issueJwtHS256(claimSet, sharedSecret);

  print('JWT: "$token"\n');

  return token;
}

void receiverProcessesJwt(String token) {
  try {
    // Verify the signature in the JWT and extract its claim set
    final decClaimSet = verifyJwtHS256Signature(token, sharedSecret);
    print(decClaimSet.toJson());

    // Validate the claim set

    decClaimSet.validate(issuer: 'teja', audience: 'client2.example.com');

    // Use values from claim set

    if (decClaimSet.subject != null) {
      print('JWT_ID: "${decClaimSet.jwtId}"');
    }
    if (decClaimSet.jwtId != null) {
      print('subject: "${decClaimSet.subject}"');
    }
    if (decClaimSet.issuedAt != null) {
      print('iat: ${decClaimSet.issuedAt}');
    }
    if (decClaimSet.containsKey('typ')) {
      dynamic v = decClaimSet['typ'];
      if (v is String) {
        print('typ: "$v"');
      } else {
        print('Error: unexpected type for "typ" claim');
      }
    }
  } on JwtException catch (e) {
    print('Error: bad JWT: $e');
  }
}

String _randomString(int length) {
  const chars =
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  final rnd = new Random(new DateTime.now().millisecondsSinceEpoch);
  final buf = new StringBuffer();

  for (var x = 0; x < length; x++) {
    buf.write(chars[rnd.nextInt(chars.length)]);
  }
  return buf.toString();
}
