// Copyright (c) 2017, teja. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library jaguar_session_mongo.src;

import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:mongo_dart/mongo_dart.dart';
import 'package:jaguar/jaguar.dart';
import 'package:jaguar_data_store/jaguar_data_store.dart';
import 'package:jaguar_mongo_data_store/jaguar_mongo_data_store.dart';
import 'package:jaguar_serializer/jaguar_serializer.dart';
import 'package:crypto/crypto.dart';

part 'model.dart';

/// MongoDb based session manager that stores session identifier on Cookie
///
/// Stores session data on MongoDb. Stores the session identifier on Cookie.
class MgoCookieSession extends SessionManager {
  /// Name of the cookie on which session identifier is stored
  final String cookieName;

  /// Duration after which the session is expired
  final Duration expiry;

  final MapCoder coder;

  MgoCookieSession({this.cookieName = 'session', this.expiry, String hmacKey})
      : coder = MapCoder(
            signer: hmacKey != null ? Hmac(sha256, hmacKey.codeUnits) : null);

  MgoCookieSession.withCoder(this.coder,
      {this.cookieName = 'session', this.expiry});

  /// Parses session from the given [request]
  Future<Session> parse(Context ctx) async {
    Cookie cook = ctx.cookies[cookieName];
    if(cook == null) return Session.newSession({});
    Map<String, String> values = coder.decode(cook.value);

    if (values == null) return newSession();

    if (values['sid'] is! String) return newSession();

    final String timeStr = values['sct'];
    if (timeStr is! String) return newSession();

    final int timeMilli = int.tryParse(timeStr);
    if (timeMilli == null) return newSession();

    final time = new DateTime.fromMillisecondsSinceEpoch(timeMilli);

    if (expiry != null) {
      final Duration diff = DateTime.now().difference(time);
      if (diff > expiry) {
        return newSession();
      }
    }

    final String id = values['sid'];

    if (!_isValidMgoId(id)) return newSession();

    final Db db = ctx.getVariable<Db>();
    final dataStore = MongoDataStore<_SessionData>(_serializer, "session", db);

    final _SessionData data = await dataStore.getById(id);

    return new Session(values['sid'], data.data, time);
  }

  /// Writes session data ([session]) to the Response ([resp]) and returns new
  /// response
  Future<void> write(Context ctx) async {
    if (!ctx.sessionNeedsUpdate) return;

    final Db db = ctx.getVariable<Db>();
    final dataStore = MongoDataStore<_SessionData>(_serializer, "session", db);

    final Session session = ctx.parsedSession;

    if (_isValidMgoId(session.id)) {
      if (session.keys.length > 0) {
        _SessionData data = new _SessionData();
        data.id = session.id;
        session.keys.forEach((k) => data.data[k] = session[k]);
        await dataStore.upsertById(session.id, data);
      } else {
        await dataStore.removeById(session.id);
      }
      final Map<String, String> values = session.asMap;
      values['sid'] = session.id;
      values['sct'] = session.createdTime.millisecondsSinceEpoch.toString();
      final cook = new Cookie(cookieName, coder.encode(values));
      cook.path = '/';
      ctx.response.cookies.add(cook);
    } else {
      final Map<String, String> values = session.asMap;
      values['sid'] = '0' * 24;
      final cook = new Cookie(cookieName, coder.encode(values));
      ctx.response.cookies.add(cook);
    }
  }

  static Session newSession() =>
      Session.newSession({}, id: ObjectId().toHexString());
}

final String _zeroId = '0' * 24;
bool _isValidMgoId(String hexString) {
  if (hexString is! String) return false;

  if (hexString.length != 24) return false;

  if (hexString == (_zeroId)) return false;

  if (!hexString.toUpperCase().codeUnits.every(_isCharHex)) return false;

  return true;
}

bool _isCharHex(int code) {
  if (code >= 48 && code <= 57) return true;

  if (code >= 65 && code <= 70) return true;

  return false;
}
