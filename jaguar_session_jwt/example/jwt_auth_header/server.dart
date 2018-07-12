library example.basic_auth.server;

import 'dart:async';

import 'package:jaguar/jaguar.dart';
import 'package:jaguar_reflect/jaguar_reflect.dart';
import 'package:jaguar_auth/jaguar_auth.dart';
import 'package:jaguar_session_jwt/jaguar_session_jwt.dart';

import 'package:jaguar_example_session_models/jaguar_example_session_models.dart';

/// JWT Authentication context used by [JwtSession]
const jwtConfig = const JwtConfig('sdgdflgujsdgndsflkgjsdlnwertwert78676',
    issuer: 'jaguar.com');

/// This route group contains login and logout authentication routes
@Controller()
//You must provide an instance of SessionManager through sessionManager parameter
class AuthRoutes {
  @PostJson(path: '/login')
  Future<Map> login(Context ctx) async {
    final User user = await FormAuth.authenticate<User>(ctx);
    return {'msg': 'Successufully logged in as ${user.username}!'};
  }

  @Post(path: '/logout')
  Future<void> logout(Context ctx) async {
    (await ctx.session).clear();
  }
}

/// Collection of routes that need authorization
@Controller(path: '/book')
class StudentRoutes {
  @GetJson(path: '/all')
  Future<List<Book>> getAll(Context ctx) async {
    await Authorizer.authorize<User>(ctx);
    return books.values.toList();
  }
}

@Controller()
class LibraryApi {
  @IncludeHandler()
  final auth = AuthRoutes();

  @IncludeHandler()
  final student = StudentRoutes();
}

main() async {
  final server = Jaguar(port: 10000, sessionManager: JwtSession(jwtConfig));
  server.userFetchers[User] = DummyUserFetcher(users);
  server.add(reflect(LibraryApi()));

  server.log.onRecord.listen(print);
  await server.serve(logRequests: true);
}
