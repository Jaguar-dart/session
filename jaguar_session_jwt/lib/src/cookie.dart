part of jaguar_auth.session;

/// JWT based session manager with Cookie as transport mechanism
///
/// Stores all session as JWT token on a Cookie
///
///     server() async {
///       final jaguar =
///       new Jaguar(sessionManager: new JwtCookieSession(jwtConfig));
///       jaguar.addApi(reflect(new LibraryApi()));
///       await jaguar.serve();
///     }
class JwtCookieSession extends Object
    with _BaseJwtSession
    implements SessionManager {
  /// Name of the cookie on which session data is stored
  final String cookieName;

  /// JWT configuration used to issue a JWT token
  final JwtConfig config;

  /// Information required to validate a JWT token
  final JwtValidationConfig validationConfig;

  JwtCookieSession(this.config,
      {this.validationConfig: const JwtValidationConfig(),
      this.cookieName = 'session'});

  /// Parses session from the given [request]
  Future<Session> parse(Context context) async {
    for (Cookie cook in context.req.cookies) {
      if (cook.name == cookieName) return decodeJwt(cook.value);
    }
    return new Session.newSession({});
  }

  /// Writes [response] with session details
  Response write(Context context, Response resp) {
    if (!context.sessionNeedsUpdate) return resp;

    final Session session = context.parsedSession;
    final cook = new Cookie(cookieName, encodeJwt(session.asMap));
    cook.path = '/';
    resp.cookies.add(cook);
    return resp;
  }
}
