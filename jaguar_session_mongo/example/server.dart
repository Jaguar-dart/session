library example.basic_auth.server;

import 'dart:async';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_reflect/jaguar_reflect.dart';
import 'package:jaguar_auth/jaguar_auth.dart';
import 'package:jaguar_session_mongo/jaguar_session_mongo.dart';
import 'package:jaguar_mongo/jaguar_mongo.dart';

import 'package:jaguar_example_session_models/jaguar_example_session_models.dart';

final pool = MongoPool('mongodb://localhost:27017/example');

/// This route group contains login and logout routes
@GenController()
class AuthRoutes extends Controller {
  @PostJson(path: '/login')
  User login(Context ctx) => ctx.getVariable<User>();

  @override
  FutureOr<void> before(Context ctx) async {
    await pool.call(ctx);
    await FormAuth.authenticate<User>(ctx);
  }
}

@GenController(path: '/book')
class StudentRoutes extends Controller {
  @GetJson()
  List<Book> getAllBooks(Context ctx) => books.values.toList();

  @override
  FutureOr<void> before(Context ctx) async {
    await pool.call(ctx);
    await Authorizer<User>().call(ctx);
  }
}

@GenController()
class LibraryApi extends Controller {
  @IncludeController()
  final auth = AuthRoutes();

  @IncludeController()
  final books = StudentRoutes();
}

main() async {
  final server = Jaguar(port: 10000, sessionManager: MgoSession());
  server.userFetchers[User] = DummyUserFetcher(users);

  server..add(reflect(LibraryApi()));

  server.log.onRecord.listen(print);
  await server.serve(logRequests: true);
}
