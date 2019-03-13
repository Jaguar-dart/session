library test.encode;

import 'package:jaguar_jwt/src/secure_compare.dart';
import 'package:test/test.dart';

void main() {
  group('Secure Compare', () {
    test('secureCompareIntList', () {
      List<int> a = [255, 4, 3, 6];
      List<int> b = [255, 4, 3, 6];
      List<int> c = [123, 4, 3, 6];
      List<int> d = [123, 4, 3];

      // Both lists are equal.
      expect(secureCompareIntList(a, b), true);
      // The lists are different.
      expect(secureCompareIntList(a, c), false);
      // The lists have different length.
      expect(secureCompareIntList(a, d), false);
    });
  });
}
