import 'dart:collection';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:jaguar_jwt/src/secure_compare.dart';

import 'b64url_rfc7515.dart';
import 'claim.dart';

import 'package:rsa_pkcs/rsa_pkcs.dart' as rsa;

String issueJwtRsaSha256(JwtClaim claimSet,
    {String? privateKey, String? publicKey, String? password}) {
  // Use SplayTreeMap to ensure ordering in JSON: i.e. alg before typ.
  // Ordering is not required for JWT: it is deterministic and neater.
  final header = SplayTreeMap<String, String>.from(
      <String, String>{'alg': 'HS256', 'typ': 'JWT'});

  final String encHdr = B64urlEncRfc7515.encodeUtf8(json.encode(header));
  final String encPld =
      B64urlEncRfc7515.encodeUtf8(json.encode(claimSet.toJson()));
  final String data = '${encHdr}.${encPld}';

  throw UnimplementedError();
}

class RsaSha256Signer {
  final rsa.RSAPrivateKey? privateKey;
  final rsa.RSAPublicKey? publicKey;

  RsaSha256Signer(this.publicKey, this.privateKey);

  factory RsaSha256Signer.make(
      {String? privateKey, String? publicKey, String? password}) {
    final parser = rsa.RSAPKCSParser();

    rsa.RSAPrivateKey? priv;
    if (privateKey != null) {
      final pair = parser.parsePEM(privateKey, password: password);
      if (pair.private == null) {
        throw ArgumentError('Invalid private key provided');
      }
      priv = pair.private;
    }

    rsa.RSAPublicKey? pub;
    if (publicKey != null) {
      final pair = parser.parsePEM(publicKey, password: password);
      if (pair.public == null) {
        throw ArgumentError('Invalid public key provided');
      }
      pub = pair.public;
    }

    return RsaSha256Signer(pub, priv);
  }
}
