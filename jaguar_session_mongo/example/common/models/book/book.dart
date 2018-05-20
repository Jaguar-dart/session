library jwt_auth.example.models;

import 'dart:convert';
import 'package:jaguar/jaguar.dart';

/// Model for Book
class Book {
  /// Id of the book
  String id;

  /// Name of the book
  String name;

  /// Authors of the book
  String author;

  Book.make(this.id, this.name, this.author) {}

  Book.FromQueryParam(QueryParams params) {
    fromMap({'name': params['name'], 'authors': params['authors']});
  }

  /// Converts to Map
  Map toMap() => {
        'id': id,
        'name': name,
        'author': author,
      };

  // Converts to JSON
  String toJson() {
    return JSON.encode(toMap());
  }

  /// Builds from JSON
  void fromJson(String json) {
    dynamic map = JSON.decode(json);

    if (map is Map) {
      fromMap(map);
    }
  }

  /// Builds from Map
  void fromMap(Map map) {
    if (map['id'] is String) {
      id = map['id'];
    }

    if (map['name'] is String) {
      name = map['name'];
    }

    if (map['author'] is String) {
      author = map['author'];
    }
  }

  void validate() {
    if (id is! String) {
      //TODO
    }

    if (id.isEmpty) {
      //TODO
    }

    if (name is! String) {
      //TODO
    }

    if (name.isEmpty) {
      //TODO
    }

    if (author is! String) {
      //TODO
    }

    if (author.isEmpty) {
      //TODO
    }
  }
}
