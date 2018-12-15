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
      .before(cookieInterceptor)
      .urlEncodedForm({'username': 'teja', 'password': 'word'})
      .go()
      .then((_) => print("Login successful!"));
  List<Book> books = await get(base)
      .path('/book')
      .before(cookieInterceptor)
      .list(convert: Book.fromMap);
  print(books);
}
