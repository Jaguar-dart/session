/// Compares two byte lists securely.
///
/// This tries to mitigate timing based attacks.
/// https://en.wikipedia.org/wiki/Timing_attack
///
/// Returns [true] if [a] and [b] are equal.
///
///     bool isEqual = secureCompareBytes(signature, computed);
bool secureCompareIntList(List<int> a, List<int> b) {
  // Exit early if their lengths don't match.
  //
  // An attacker could figure out the length of the key used to sign the JWT.
  // But, if the key is sufficiently large enough, it'll still take them a
  // long time to go through all the possible permutations.
  if (a.length != b.length) {
    return false;
  }

  int c = 0;
  for (int i = 0; i < a.length; i++) {
    // XOR prevents the compiler from performing optimizations, making sure
    // this loop runs [a.length] iterations every single time.
    c += a[i] ^ b[i];
  }

  // If [c == 0], then that means every single  element of [a] and [b] equal each other.
  // https://en.wikipedia.org/wiki/Bitwise_operation#XOR
  return c == 0;
}
