part of jaguar_session_mongo.src;

class _SessionData implements Idied<String> {
  String id;

  Map<String, String> data = {};
}

class _SessionDataSerializer extends Serializer<_SessionData> {
  _SessionData createModel() => new _SessionData();

  /// Encodes model to [Map]
  Map toMap(_SessionData model, {bool withType: false, String typeKey}) => {
        "_id": ObjectId.parse(model.id),
        "data": model.data,
      };

  /// Decodes model from [Map]
  _SessionData fromMap(Map map, {_SessionData model}) {
    final _SessionData ret = super.fromMap(map, model: model);
    if (map['_id'] is ObjectId) {
      ObjectId id = map['_id'];
      ret.id = id.toHexString();
    }
    if (map['data'] is Map<String, String>) {
      ret.data = map['data'];
    } else {
      ret.data = <String, String>{};
    }
    return ret;
  }

  String modelString() => '_SessionData';
}

final _SessionDataSerializer _serializer = new _SessionDataSerializer();
