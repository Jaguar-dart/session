library jaguar_jwt.example;

import 'package:jaguar_jwt/jaguar_jwt.dart';

void main() {
  final key = 'dfsdffasdfdgdfgdfg456456456';
  final claimSet = new JwtClaim(
      subject: 'kleak',
      issuer: 'teja',
      audience: <String>['example.com', 'hello.com'],
      payload: {'k': 'v'});
  String token = issueJwtHS256(claimSet, key);
  print(token);

  final JwtClaim decClaimSet = verifyJwtHS256Signature(token, key);
  print(decClaimSet.toJson());

  decClaimSet.validate(issuer: 'teja', audience: 'hello.com');
}
