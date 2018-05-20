library example.basic_auth.client;

import 'package:http/http.dart' as http;
import 'package:jaguar_client/jaguar_client.dart';
import '../../common/models/models.dart';

final JsonClient _client =
    new JsonClient(new http.Client(), repo: jsonRepo, manageCookie: true);

const String kHostname = 'localhost';
const int kPort = 10000;
final String basePath = 'http://$kHostname:$kPort';

void printResponse(JsonResponse resp) {
  print("body: ${resp.bodyStr}");
  print("deserialized: ${resp.deserialize()}");
  print("statusCode: ${resp.statusCode}");
  print("Headers: ${resp.headers}");
  print('=========================');
}

getOne() async {
  final JsonResponse resp = await _client.get(basePath + '/api/book/0');
  printResponse(resp);
}

getAll() async {
  final JsonResponse resp = await _client.get(basePath + '/api/book');
  printResponse(resp);
}

login() async {
  final JsonResponse resp = await _client.authenticateBasic(
      new AuthPayload('teja', 'word'),
      url: basePath + '/api/login',
      authHeader: true);
  printResponse(resp);
}

client() async {
  await login();
  await getOne();
  await getAll();
}
