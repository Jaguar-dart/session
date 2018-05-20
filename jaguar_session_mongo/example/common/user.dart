library example.common.user;

import 'dart:async';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_auth/jaguar_auth.dart';

class User implements AuthorizationUser {
  final String id;

  final String username;

  final String password;

  const User(this.id, this.username, this.password);

  String get authorizationId => id;
}

const Map<String, User> kUsers = const {
  '0': const User('0', 'teja', 'word'),
  '1': const User('1', 'kleak', 'pass'),
};

const WhiteListPasswordChecker modelManager =
    const WhiteListPasswordChecker(kUsers);

/// Model manager to authenticate against a static list of user models
class WhiteListPasswordChecker implements AuthModelManager {
  /// User models to white list
  final Map<String, User> models;

  /// Password hasher
  final Hasher hasher;

  const WhiteListPasswordChecker(Map<String, User> models, {Hasher hasher})
      : models = models ?? const {},
        hasher = hasher ?? const NoHasher();

  Future<User> authenticate(
      Context ctx, String username, String password) async {
    User model = await fetchByAuthenticationId(ctx, username);

    if (model == null) {
      return null;
    }

    if (!hasher.verify(password, model.password)) {
      return null;
    }

    return model;
  }

  Future<User> fetchByAuthenticationId(Context ctx, String authName) async =>
      models.values.firstWhere((model) => model.username == authName,
          orElse: () => null);

  Future<User> fetchByAuthorizationId(Context ctx, String sessionId) async {
    if (!models.containsKey(sessionId)) {
      return null;
    }

    return models[sessionId];
  }
}
