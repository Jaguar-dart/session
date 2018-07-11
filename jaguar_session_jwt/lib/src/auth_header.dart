part of jaguar_auth.session;

/// JWT based session manager with `authorization` header as transport mechanism
///
/// Stores all session as JWT token on `authorization` header
///
///     server() async {
///       final jaguar = Jaguar(port: 10000, sessionManager: new JwtHeaderSession(jwtConfig));
///       jaguar.add(reflect(LibraryApi()));
///       await jaguar.serve();
///     }
class JwtHeaderSession extends Object
    with _BaseJwtSession
    implements SessionManager {
  /// JWT configuration used to issue a JWT token
  final JwtConfig config;

  /// Information required to validate a JWT token
  final JwtValidationConfig validationConfig;

  JwtHeaderSession(this.config,
      {this.validationConfig: const JwtValidationConfig()});

  /// Parses session from the given [request]
  Future<Session> parse(Context context) async {
    String authHeaderStr =
        context.req.headers.value(HttpHeaders.authorizationHeader);

    final jwtToken =
        new AuthHeaderItem.fromHeaderBySchema(authHeaderStr, kScheme);

    // Is the token present?
    if (jwtToken is! AuthHeaderItem) {
      return new Session.newSession({});
    }

    return decodeJwt(jwtToken.credentials);
  }

  /// Writes [response] with session details
  void write(Context context) {
    if (!context.sessionNeedsUpdate) return;

    final String oldHeader =
        context.response.headers.value(HttpHeaders.authorizationHeader);
    final headers = AuthHeaders.fromHeaderStr(oldHeader);
    headers.addItem(
        AuthHeaderItem(kScheme, encodeJwt(context.parsedSession.asMap)));
    context.response.headers
        .set(HttpHeaders.authorizationHeader, headers.toString());
  }

  static const String kScheme = 'Bearer';
}
