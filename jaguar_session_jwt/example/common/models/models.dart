library auth.example.models;

import 'package:jaguar_common/jaguar_common.dart';
import 'package:jaguar_serializer/jaguar_serializer.dart';

part 'models.g.dart';

final JsonRepo jsonRepo =
    new JsonRepo(serializers: [Book.serializer, User.serializer]);

/// Model for Book
class Book {
  /// Id of the book
  String id;

  /// Name of the book
  String name;

  /// Authors of the book
  String author;

  Book.make(this.id, this.name, this.author);

  Book();

  String toString() => 'Book(id: $id, name: $name, author: $author)';

  static final Serializer<Book> serializer = new BookSerializer();
}

@GenSerializer()
class BookSerializer extends Serializer<Book> with _$BookSerializer {
  @override
  Book createModel() => new Book();
}

class User implements AuthorizationUser {
  String id;

  String username;

  String password;

  User(this.id, this.username, this.password);

  User.empty();

  String get loginId => username;

  String get loginPassword => password;

  String get authorizationId => id;

  String toString() => 'User(id: $id, username: $username)';

  static final Serializer<User> serializer = new UserSerializer();
}

@GenSerializer(
    ignore: const ['password', 'loginId', 'loginPassword', 'authorizationId'])
class UserSerializer extends Serializer<User> with _$UserSerializer {
  @override
  User createModel() => new User.empty();
}
