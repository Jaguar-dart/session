library jaguar_auth.session;

import 'dart:io';
import 'dart:async';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

part 'common.dart';

/// JWT based session manager.
///
/// Use [io] to configure how session data is transported. Built-in options are:
/// 1. [SessionIoCookie]: Stores token in cookie
/// 2. [SessionIoAuthHeader]: Stores token in authorization header
/// 3. [SessionIoHeader]: Stores token in header
///
/// By default, [JwtSession] uses [SessionIoAuthHeader].
///
///     server() async {
///       final server = Jaguar(sessionManager: JwtSession(jwtConfig));
///       server.add(reflect(LibraryApi()));
///       await server.serve();
///     }
class JwtSession implements SessionManager {
  final SessionIo io;

  final JwtMapCoder coder;

  JwtSession(JwtConfig config,
      {JwtValidationConfig validationConfig,
      this.io: const SessionIoAuthHeader()})
      : coder = JwtMapCoder(config, validationConfig: validationConfig);

  /// Parses session from the given [request]
  Future<Session> parse(Context context) async {
    String raw = io.read(context);
    if (raw == null) return Session.newSession({});
    Map<String, String> values = coder.decode(raw);
    if (values == null) return Session.newSession({});
    return Session(values['sid'], values, DateTime.parse(values['sct']));
  }

  /// Writes [response] with session details
  void write(Context context) {
    if (!context.sessionNeedsUpdate) return;

    final Session session = context.parsedSession;
    io.write(context, coder.encode(session.asMap));
  }
}
