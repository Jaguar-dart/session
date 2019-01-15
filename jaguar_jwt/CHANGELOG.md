# Changelog

## TBD

+ Added support for optional Not Before (`nbf`) time claims.
+ Fixed validation to reject token when current time equals the Expiry time.
+ Added support for custom payload name.
+ Added more validation unit tests.
+ Fixed generation of JWT to use correct Base64url Encoding.

## 2.1.2

+ Fixed when `typ` is not present

## 2.1.1

+ Dart 2 compatibility
