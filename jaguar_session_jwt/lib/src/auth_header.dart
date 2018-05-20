part of jaguar_auth.session;

/// JWT based session manager with `authorization` header as transport mechanism
///
/// Stores all session as JWT token on `authorization` header
///
///     server() async {
///       final jaguar =
///       new Jaguar(port: 10000, sessionManager: new JwtHeaderSession(jwtConfig));
///       jaguar.addApi(reflect(new LibraryApi()));
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
    String authHeaderStr = context.req.headers.value(HttpHeaders.AUTHORIZATION);

    final jwtToken =
        new AuthHeaderItem.fromHeaderBySchema(authHeaderStr, kScheme);

    // Is the token present?
    if (jwtToken is! AuthHeaderItem) {
      return new Session.newSession({});
    }

    return decodeJwt(jwtToken.credentials);
  }

  /// Writes [response] with session details
  Response write(Context context, Response resp) {
    if (!context.sessionNeedsUpdate) return resp;

    final String oldHeader = resp.headers.value(HttpHeaders.AUTHORIZATION);
    final headers = new AuthHeaders.fromHeaderStr(oldHeader);
    headers.addItem(
        new AuthHeaderItem(kScheme, encodeJwt(context.parsedSession.asMap)));
    resp.headers.set(HttpHeaders.AUTHORIZATION, headers.toString());

    return resp;
  }

  static const String kScheme = 'Bearer';
}
