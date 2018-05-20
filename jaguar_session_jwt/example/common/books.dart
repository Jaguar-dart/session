library example.common.data;

import 'dart:async';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_auth/jaguar_auth.dart';

import 'models/models.dart';

final Map<String, Book> books = {
  '0': new Book.make('0', 'Book0', 'Author0'),
  '1': new Book.make('1', 'Book1', 'Author1'),
  '2': new Book.make('2', 'Book2', 'Author2'),
};

final Map<String, User> kUsers = {
  '0': new User('0', 'teja', 'word'),
  '1': new User('1', 'kleak', 'pass'),
};

final WhiteListPasswordChecker kModelManager =
    new WhiteListPasswordChecker(kUsers);

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

    if (!hasher.verify(password, model.loginPassword)) {
      return null;
    }

    return model;
  }

  Future<User> fetchByAuthenticationId(Context ctx, String authName) async =>
      models.values
          .firstWhere((model) => model.loginId == authName, orElse: () => null);

  Future<User> fetchByAuthorizationId(Context ctx, String sessionId) async {
    if (!models.containsKey(sessionId)) {
      return null;
    }

    return models[sessionId];
  }
}
