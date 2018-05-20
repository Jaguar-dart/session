// Copyright (c) 2016, Ravi Teja Gudapati. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

/// JWT session managers for Jaguar
///
/// JWT session on Cookie
///
/// JWT based session manager with Cookie as transport mechanism. This session
/// manager stores all session as JWT token on a Cookie.
///
/// 1. `cookieName`
/// Name of the Cookie on which the session data is stored.
/// 2. `config`
/// JWT configuration used to issue a JWT token
/// 3. `validationConfig`
/// Information required to validate a JWT token
///
/// ## Using JwtCookieSession
///
///     server() async {
///       final jaguar =
///       new Jaguar(sessionManager: new JwtCookieSession(jwtConfig));
///       jaguar.addApi(reflect(new LibraryApi()));
///       await jaguar.serve();
///     }
///
/// # JWT session on authorization header
///
/// JWT based session manager with `authorization` header as transport mechanism.
/// This session manager stores all session as JWT token on `authorization` header.
///
/// 1. `config`
/// JWT configuration used to issue a JWT token
/// 2. `validationConfig`
/// Information required to validate a JWT token
///
/// ## Using JwtHeaderSession
///
///     server() async {
///       final jaguar =
///       new Jaguar(port: 10000, sessionManager: new JwtHeaderSession(jwtConfig));
///       jaguar.addApi(reflect(new LibraryApi()));
///       await jaguar.serve();
///     }
library jaguar_session;

export 'src/session.dart';
