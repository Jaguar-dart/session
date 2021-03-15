import 'claim.dart';

/// Converts a JwtClaim into a multi-line String for display.
@override
String prettify(JwtClaim claim) {
  final buf = StringBuffer('{\n');

  var hadPrev = false;
  for (String claimName in claim.claimNames(includeRegisteredClaims: true)) {
    if (hadPrev) buf.write(',\n');
    buf.write(_toStringIndent);
    _toStringDump(claimName, buf);
    buf.write(': ');
    _toStringDump(claim[claimName], buf, 1);
    hadPrev = true;
  }

  if (hadPrev) buf.write('\n');
  buf.write('}');

  return buf.toString();
}

const String _toStringIndent = '  ';

void _toStringDump(Object? value, StringBuffer buf, [int indent = 0]) {
  if (value is Iterable<Object>) {
    // Dump an Iterable
    buf.write('[\n');
    var hadPrev = false;
    for (var v in value) {
      if (hadPrev) {
        buf.write(',\n');
      }
      buf.write(_toStringIndent * (indent + 1));
      _toStringDump(v, buf, indent + 1);
      hadPrev = true;
    }
    if (hadPrev) {
      buf.write('\n');
    }
    buf..write(_toStringIndent * (indent))..write(']');
  } else if (value is Map) {
    // Dump a Map
    buf.write('{\n');
    var hadPrev = false;
    for (var k in value.keys) {
      if (hadPrev) {
        buf.write(',\n');
      }
      buf.write(_toStringIndent * (indent + 1));
      _toStringDump(k, buf, 0);
      buf.write(': ');
      _toStringDump(value[k], buf, indent + 1);
      hadPrev = true;
    }
    if (hadPrev) {
      buf.write('\n');
    }
    buf..write(_toStringIndent * (indent))..write('}');
  } else if (value is String) {
    // Dump a String value
    final escValue = value..replaceAll('\\', '\\\\')..replaceAll('"', '\\"');
    buf.write('"$escValue"');
  } else if (value is DateTime) {
    // Dump a DateTime value
    buf.write('<$value>');
    // buf.write('DateTime.parse("$value")');
  } else {
    // Dump some other
    buf.write(value);
  }
}
