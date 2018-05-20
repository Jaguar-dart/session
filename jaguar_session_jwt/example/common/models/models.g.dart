// GENERATED CODE - DO NOT MODIFY BY HAND

part of auth.example.models;

// **************************************************************************
// Generator: SerializerGenerator
// Target: class BookSerializer
// **************************************************************************

abstract class _$BookSerializer implements Serializer<Book> {
  Map toMap(Book model, {bool withType: false, String typeKey}) {
    Map ret = new Map();
    if (model != null) {
      if (model.id != null) {
        ret["id"] = model.id;
      }
      if (model.name != null) {
        ret["name"] = model.name;
      }
      if (model.author != null) {
        ret["author"] = model.author;
      }
      if (modelString() != null && withType) {
        ret[typeKey ?? defaultTypeInfoKey] = modelString();
      }
    }
    return ret;
  }

  Book fromMap(Map map, {Book model, String typeKey}) {
    if (map is! Map) {
      return null;
    }
    if (model is! Book) {
      model = createModel();
    }
    model.id = map["id"];
    model.name = map["name"];
    model.author = map["author"];
    return model;
  }

  String modelString() => "Book";
}

// **************************************************************************
// Generator: SerializerGenerator
// Target: class UserSerializer
// **************************************************************************

abstract class _$UserSerializer implements Serializer<User> {
  Map toMap(User model, {bool withType: false, String typeKey}) {
    Map ret = new Map();
    if (model != null) {
      if (model.id != null) {
        ret["id"] = model.id;
      }
      if (model.username != null) {
        ret["username"] = model.username;
      }
      if (modelString() != null && withType) {
        ret[typeKey ?? defaultTypeInfoKey] = modelString();
      }
    }
    return ret;
  }

  User fromMap(Map map, {User model, String typeKey}) {
    if (map is! Map) {
      return null;
    }
    if (model is! User) {
      model = createModel();
    }
    model.id = map["id"];
    model.username = map["username"];
    return model;
  }

  String modelString() => "User";
}
