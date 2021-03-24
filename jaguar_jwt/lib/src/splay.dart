import 'dart:collection';

/// Utility functions to recursively create a SplayTreeMap from a Map.
///
/// This is used by the JWT issuing function to convert Claim Values that are
/// Maps (and Maps nested inside Claim Values) into a SplayTreeMap, so that the
/// JSON that is produced has the member names in alphabetical order.
///
/// Ordering is not a requirement for JWT, but it makes the token deterministic
/// which is nicer.
SplayTreeMap<String, dynamic> _splayify(Map map) {
  final data = SplayTreeMap<String, dynamic?>();

  map.forEach((k, v) {
    if (k is String) {
      data[k] = splay(v);
    } else {
      throw const FormatException('Map with non-String key');
    }
  });

  return data;
}

/// Splays
dynamic? splay(dynamic? value) {
  if (value is Iterable) {
    return value.map<dynamic>(splay).toList();
  } else if (value is Map) {
    return _splayify(value);
  } else {
    return value;
  }
}
