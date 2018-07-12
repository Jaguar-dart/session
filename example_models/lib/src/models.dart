library auth.example.models;

import 'package:jaguar_common/jaguar_common.dart';
import 'package:jaguar_serializer/jaguar_serializer.dart';

part 'models.jser.dart';

/// Model for Book
class Book {
  /// Id of the book
  String id;

  /// Name of the book
  String name;

  /// Authors of the book
  String author;

  Book({this.id, this.name, this.author});

  static Book fromMap(Map map) => serializer.fromMap(map);

  Map toJson() => serializer.toMap(this);

  String toString() => toJson()?.toString();

  static final serializer = BookSerializer();
}

@GenSerializer()
class BookSerializer extends Serializer<Book> with _$BookSerializer {}

class User implements PasswordUser {
  String id;

  String username;

  String password;

  User({this.id, this.username, this.password});

  static User fromMap(Map map) => serializer.fromMap(map);

  Map toJson() => serializer.toMap(this);

  String get authorizationId => id;

  String toString() => toJson()?.toString();

  static final serializer = UserSerializer();
}

@GenSerializer(ignore: const ['password', 'authorizationId'])
class UserSerializer extends Serializer<User> with _$UserSerializer {}
