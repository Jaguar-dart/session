library example.jwt_cookie.server;

import 'dart:async';

import 'package:jaguar/jaguar.dart';
import 'package:jaguar_reflect/jaguar_reflect.dart';
import 'package:jaguar_auth/jaguar_auth.dart';
import 'package:jaguar_session_jwt/jaguar_session_jwt.dart';
import 'package:jaguar_serializer/jaguar_serializer.dart';
import 'package:jaguar_json/jaguar_json.dart';

import '../../common/models/models.dart';
import '../../common/books.dart';

/// JWT Authentication context used by [JwtCookieSession]
const jwtConfig = const JwtConfig('sdgdflgujsdgndsflkgjsdlnwertwert78676',
    issuer: 'jaguar.com');

class BaseApi extends Object with JsonRoutes {
  JsonRepo get repo => jsonRepo;

  BasicAuth basicAuth(Context ctx) =>
      new BasicAuth(kModelManager, authorizationIdKey: 'sub');

  Authorizer authorizer(Context ctx) =>
      new Authorizer(kModelManager, authorizationIdKey: 'sub');
}

/// This route group contains login and logout authentication routes
@Api()
class AuthRoutes extends BaseApi {
  @Post(path: '/login')
  // Wrap [BasicAuth] interceptor to authenticate
  @WrapOne(#basicAuth)
  Response<String> login(Context ctx) {
    final User user = ctx.getInterceptorResult<User>(BasicAuth);
    return toJson(user);
  }

  @Post(path: '/logout')
  Future<Null> logout(Context ctx) async {
    (await ctx.session).clear();
  }
}

/// Collection of routes that need authorization
@Api(path: '/book')
// Wrap [Authorizer] interceptor to authorize requests
@WrapOne(#authorizer)
class StudentRoutes extends BaseApi {
  @Get()
  Response<String> getAllBooks(Context ctx) {
    // Authorized user can be obtained from Authorizer as Input
    User user = ctx.getInterceptorResult(Authorizer);
    print(user.username);
    return toJson(books.values);
  }

  @Get(path: '/:id')
  Response<String> getBook(Context ctx) {
    String id = ctx.pathParams.get('id');
    Book book = books[id];
    return toJson(book);
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
  final jaguar =
      new Jaguar(port: 10000, sessionManager: new JwtCookieSession(jwtConfig));
  jaguar.addApi(reflect(new LibraryApi()));
  await jaguar.serve();
}
