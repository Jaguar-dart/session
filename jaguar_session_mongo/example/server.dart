library example.basic_auth.server;

import 'dart:async';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_reflect/jaguar_reflect.dart';
import 'package:jaguar_auth/jaguar_auth.dart';
import 'package:jaguar_session_mongo/jaguar_session_mongo.dart';
import 'package:jaguar_mongo/jaguar_mongo.dart';

import 'package:jaguar_example_session_models/jaguar_example_session_models.dart';

final pool = MongoPool('mongodb://localhost:27017/example');

Future<void> mongoInterceptor(Context ctx) => pool.injectInterceptor(ctx);

/// This route group contains login and logout routes
@Controller()
@Intercept([mongoInterceptor])
class AuthRoutes {
  @PostJson(path: '/login')
  @Intercept([FormAuth<User>()])
  User login(Context ctx) => ctx.getVariable<User>();
}

@Controller(path: '/book')
@Intercept([mongoInterceptor, Authorizer<User>()])
class StudentRoutes {
  @GetJson()
  List<Book> getAllBooks(Context ctx) => books.values.toList();
}

@Controller()
class LibraryApi {
  @IncludeHandler()
  final auth = AuthRoutes();

  @IncludeHandler()
  final books = StudentRoutes();
}

main() async {
  final server = Jaguar(port: 10000, sessionManager: MgoSession());
  server.userFetchers[User] = DummyUserFetcher(users);

  server..add(reflect(LibraryApi()));

  server.log.onRecord.listen(print);
  await server.serve(logRequests: true);
}
