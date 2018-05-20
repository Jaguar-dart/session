library example.basic_auth.server;

import 'dart:async';
import 'dart:io';

import 'dart:convert';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_reflect/jaguar_reflect.dart';
import 'package:jaguar_serializer/jaguar_serializer.dart';
import 'package:jaguar_json/jaguar_json.dart';

import '../../common/models/models.dart';
import '../../common/books.dart';

/// This route group contains login and logout authentication routes
@Api()
class AuthRoutes extends Object with JsonRoutes {
  JsonRepo get repo => jsonRepo;

  @Post(path: '/login/:username/:pwd')
  Future<String> login(Context ctx) async {
    String username = ctx.pathParams['username'];
    String pwd = ctx.pathParams['pwd'];
    if (username == null || pwd == null) {
      throw new Response(null, statusCode: HttpStatus.UNAUTHORIZED);
    }

    if (username != 'jaguar' || pwd != 'awesome') {
      throw new Response(null, statusCode: HttpStatus.UNAUTHORIZED);
    }

    final Session session = await ctx.session;
    //Set session information
    session['username'] = 'jaguar';
    //Update response with session information
    return JSON.encode({'msg': 'success!'});
  }

  @Post(path: '/logout')
  Future<String> logout(Context ctx) async {
    final Session session = await ctx.session;
    // Delete session
    session.clear();
    return JSON.encode({'msg': 'success!'});
  }
}

/// Collection of routes that need authorization
@Api(path: '/book')
class StudentRoutes extends Object with JsonRoutes {
  JsonRepo get repo => jsonRepo;

  @Get(path: '/all')
  Future<Response<String>> getAllBooks(Context ctx) async {
    final Session session = await ctx.session;

    //Authorize
    String username = session['username'];
    if (username is! String || username != 'jaguar') {
      throw new Response(null, statusCode: HttpStatus.UNAUTHORIZED);
    }

    return toJson(books.values);
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
  final jaguar = new Jaguar(port: 10000);
  jaguar.addApi(reflect(new LibraryApi()));
  await jaguar.serve();
}
