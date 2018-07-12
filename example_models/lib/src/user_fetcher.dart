library example.common.data;

import 'dart:async';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_auth/jaguar_auth.dart';

import 'models.dart';

final Map<String, Book> books = {
  '0': Book(id: '0', name: 'Book0', author: 'Author0'),
  '1': Book(id: '1', name: 'Book1', author: 'Author1'),
  '2': Book(id: '2', name: 'Book2', author: 'Author2'),
};

final Map<String, User> users = {
  '0': User(id: '0', username: 'teja', password: 'word'),
  '1': User(id: '1', username: 'kleak', password: 'pass'),
};

/// Model manager to authenticate against a static list of user models
class DummyUserFetcher implements UserFetcher<User> {
  /// User models to white list
  final Map<String, User> models;

  const DummyUserFetcher(Map<String, User> models, {Hasher hasher})
      : models = models ?? const {};

  Future<User> byAuthenticationId(Context ctx, String authenticationId) async =>
      models.values.firstWhere((model) => model.username == authenticationId,
          orElse: () => null);

  Future<User> byAuthorizationId(Context ctx, String sessionId) async {
    if (!models.containsKey(sessionId)) return null;
    return models[sessionId];
  }
}
