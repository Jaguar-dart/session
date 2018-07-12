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
@Controller()
class AuthRoutes {
  @PostJson(path: '/login')
  @Intercept([FormAuth<User>()])
  User login(Context ctx) => ctx.getVariable<User>();

  @Post(path: '/logout')
  Future logout(Context ctx) async {
    // Clear session data
    (await ctx.session).clear();
  }
}

@Controller(path: '/book')
@Intercept([Authorizer<User>()])
class StudentRoutes {
  @GetJson()
  List<Book> getAllBooks(Context ctx) => books.values.toList();
}

@Controller(path: '/api')
class LibraryApi {
  @IncludeHandler()
  final auth = new AuthRoutes();

  @IncludeHandler()
  final books = new StudentRoutes();
}

server() async {
  final server = Jaguar(port: 10000, sessionManager: MgoCookieSession());

  server..add(reflect(LibraryApi()));

  server.userFetchers[User] = DummyUserFetcher(users);
  await server.serve(logRequests: true);
}
