import 'dart:math';

import 'package:jaguar_jwt/jaguar_jwt.dart';

const sharedSecret = 's3cr3t';

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
      otherClaims: {
        'typ': 'authnresponse',
        'pld': {'k': 'v'}
      },
      maxAge: const Duration(minutes: 5));

  // Generate a JWT from the claim set

  final token = issueJwtHS256(claimSet, sharedSecret);

  print('jwt = "$token"');

  return token;
}

void receiverProcessesJwt(String token) {
  // Verify the signature in the JWT and extract its claim set

  final JwtClaim decClaimSet = verifyJwtHS256Signature(token, sharedSecret);

  print(decClaimSet.toJson());

  // Validate the claim set

  decClaimSet.validate(issuer: 'teja', audience: 'client2.example.com');

  assert(decClaimSet.subject == 'kleak');
  assert(decClaimSet.jwtId.isNotEmpty); // should check for uniqueness
}

const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
String _randomString(int length) {
  final rnd = new Random(new DateTime.now().millisecondsSinceEpoch);
  var buf = new StringBuffer();

  for (var x = 0; x < length; x++) {
    buf.write(chars[rnd.nextInt(chars.length)]);
  }
  return buf.toString();
}
