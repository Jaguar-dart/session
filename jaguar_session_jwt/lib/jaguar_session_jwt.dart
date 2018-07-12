// Copyright (c) 2016, Ravi Teja Gudapati. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

/// JWT session managers for Jaguar
///
///     const jwtConfig = const JwtConfig('sdgdflgujsdgndsflkgjsdlnwertwert78676',
///          issuer: 'jaguar.com');
///     main() async {
///       final server = Jaguar(sessionManager: JwtSession(jwtConfig));
///       // add routes here
///       await server.serve();
///     }
library jaguar_session;

export 'src/session.dart';
