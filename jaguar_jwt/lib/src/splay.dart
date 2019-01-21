import 'dart:collection';

/// Utility functions to recursively create a SplayTreeMap from a Map.
///
/// This is used by the JWT issuing function to convert Claim Values that are
/// Maps (and Maps nested inside Claim Values) into a SplayTreeMap, so that the
/// JSON that is produced has the member names in alphabetical order.
///
/// Ordering is not a requirement for JWT, but it makes the token deterministic
/// which is nicer.
SplayTreeMap<String, Object> _splayify(Map<Object, Object> map) {
  final data = SplayTreeMap<String, Object>();

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
Object splay(Object value) {
  if (value is Iterable) {
    return value.map<Object>(splay).toList();
  } else if (value is Map) {
    return _splayify(value);
  } else {
    return value;
  }
}
