library example.basic_auth.server;

import 'dart:async';

import 'package:jaguar/jaguar.dart';
import 'package:jaguar_reflect/jaguar_reflect.dart';
import 'package:jaguar_auth/jaguar_auth.dart';
import 'package:jaguar_session_jwt/jaguar_session_jwt.dart';

import 'package:jaguar_example_session_models/jaguar_example_session_models.dart';

/// JWT config used by [JwtSession]
const jwtConfig = const JwtConfig('sdgdflgujsdgndsflkgjsdlnwertwert78676',
    issuer: 'jaguar.com');

/// This route group contains login and logout authentication routes
@GenController()
//You must provide an instance of SessionManager through sessionManager parameter
class AuthRoutes extends Controller {
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
@GenController(path: '/book')
class StudentRoutes extends Controller {
  @GetJson(path: '/all')
  Future<List<Book>> getAll(Context ctx) async {
    await Authorizer.authorize<User>(ctx);
    return books.values.toList();
  }
}

@GenController()
class LibraryApi extends Controller {
  @IncludeController()
  final auth = AuthRoutes();

  @IncludeController()
  final student = StudentRoutes();
}

main() async {
  final server = Jaguar(port: 10000, sessionManager: JwtSession(jwtConfig));
  server.userFetchers[User] = DummyUserFetcher(users);
  server.add(reflect(LibraryApi()));

  server.log.onRecord.listen(print);
  await server.serve(logRequests: true);
}
