library example.basic_auth.client;

import 'package:http/http.dart' as http;
import 'package:jaguar_resty/jaguar_resty.dart';
import 'package:jaguar_example_session_models/jaguar_example_session_models.dart';

final cookieInterceptor = CookieJar();

final base = 'http://localhost:10000';

main() async {
  globalClient = http.IOClient();

  await post(base)
      .path('/login')
      .interceptBefore(cookieInterceptor.intercept)
      .urlEncodedForm({'username': 'teja', 'password': 'word'}).go(
          (_) => print("Login successful!"));
  List<Book> books = await get(base)
      .path('/book')
      .interceptBefore(cookieInterceptor.intercept)
      .list(Book.fromMap);
  print(books);
}
