library example.basic_auth.server;

import 'dart:async';
import 'dart:io';

import 'dart:convert';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_reflect/jaguar_reflect.dart';

import '../../../example_models/lib/src/models.dart';
import '../../../example_models/lib/src/user_fetcher.dart';

/// This route group contains login and logout authentication routes
@GenController()
class AuthRoutes extends Controller {
  @Post(path: '/login/:username/:pwd')
  Future<String> login(Context ctx) async {
    String username = ctx.pathParams['username'];
    String pwd = ctx.pathParams['pwd'];

    if (username != 'jaguar' || pwd != 'awesome') {
      throw Response(null, statusCode: HttpStatus.unauthorized);
    }

    final Session session = await ctx.session;
    //Set session information
    session['username'] = 'jaguar';
    //Update response with session information
    return json.encode({'msg': 'success!'});
  }

  @Post(path: '/logout')
  Future<String> logout(Context ctx) async {
    final Session session = await ctx.session;
    // Delete session
    session.clear();
    return json.encode({'msg': 'success!'});
  }
}

/// Collection of routes that need authorization
@GenController(path: '/book')
class StudentRoutes extends Controller {
  @GetJson(path: '/all')
  Future<List<Book>> getAllBooks(Context ctx) async {
    final Session session = await ctx.session;

    // Authorize
    if (session['username'] != 'jaguar') {
      throw Response(null, statusCode: HttpStatus.unauthorized);
    }

    return books.values.toList();
  }
}

@GenController()
class LibraryApi extends Controller {
  @IncludeController()
  final auth = new AuthRoutes();

  @IncludeController()
  final student = new StudentRoutes();
}

main() async {
  final server = Jaguar(port: 10000);

  server.add(reflect(LibraryApi()));

  server.log.onRecord.listen(print);
  await server.serve(logRequests: true);
}
