# Changelog

## TBD

+ Added support for optional Not Before (`nbf`) time claims.
+ Fixed validation to reject token when current time equals the Expiry time.
+ Added more validation unit tests.
+ Fixed generation of JWT to use correct Base64url Encoding.
+ Added general support for non-registered claims.
+ Tidy up for static analysis and Dart linter.
+ Implemented toString method for JwtClaim.
+ Allow for customized checking of the JWT header.
+ Fixed use of _splayify/_spaly in toJson and changed dynamic to Object.
+ Improved format of output produced by JwtClaim.toString().

## 2.1.2

+ Fixed when `typ` is not present

## 2.1.1

+ Dart 2 compatibility
