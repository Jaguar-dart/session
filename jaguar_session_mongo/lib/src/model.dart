part of jaguar_session_mongo.src;

class _SessionData implements Idied<String> {
  String id;

  Map<String, String> data = {};
}

class _SessionDataSerializer extends Serializer<_SessionData> {
  _SessionData createModel() => new _SessionData();

  /// Encodes model to [Map]
  Map<String, dynamic> toMap(_SessionData model) => {
        "_id": ObjectId.parse(model.id),
        "data": model.data,
      };

  /// Decodes model from [Map]
  _SessionData fromMap(Map map) {
    final _SessionData ret = super.fromMap(map);
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
