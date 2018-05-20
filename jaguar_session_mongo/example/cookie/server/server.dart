library example.basic_auth.server;

import 'dart:async';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_reflect/jaguar_reflect.dart';
import 'package:jaguar_auth/jaguar_auth.dart';
import 'package:jaguar_session_mongo/jaguar_session_mongo.dart';
import 'package:jaguar_mongo/jaguar_mongo.dart';

import '../../common/models/book/book.dart';
import '../../common/user.dart';
import '../../common/books.dart';

const String mongoUrl = 'mongodb://localhost:27017/example';

MongoDb mongo(Context ctx) => new MongoDb(mongoUrl);

Authorizer authorizer(Context ctx) => new Authorizer(modelManager);

/// This route group contains login and logout authentication routes
@Api()
@WrapOne(mongo)
//You must provide an instance of SessionManager through sessionManager parameter
class AuthRoutes {
  @Post(path: '/login')
  Future login(Context ctx) async {
    // Use [BasicAuth] to authenticate
    await BasicAuth.authenticate(ctx, modelManager);
  }

  @Post(path: '/logout')
  @WrapOne(#authorizer)
  Future<Null> logout(Context ctx) async {
    (await ctx.session).clear();
  }
}

/// Collection of routes that need authorization
@Api(path: '/book')
// Wrap [Authorizer] interceptor to authorize requests
@Wrap(const [mongo, authorizer])
class StudentRoutes {
  @Get(path: '/all')
  Response<String> getAllBooks(Context ctx) {
    List<Map> ret = books.values.map((Book book) => book.toMap()).toList();
    return Response.json(ret);
  }

  @Get(path: '/:id')
  Response<String> getBook(Context ctx) {
    final String id = ctx.pathParams['id'];
    final Book book = books[id];
    return Response.json(book.toMap());
  }
}

@Api(path: '/api')
class LibraryApi {
  @IncludeApi()
  final AuthRoutes auth = new AuthRoutes();

  @IncludeApi()
  final StudentRoutes student = new StudentRoutes();
}

server() async {
  final server =
      new Jaguar(port: 10000, sessionManager: new MgoCookieSession());
  server.addApi(reflect(new LibraryApi()));
  await server.serve();
}
