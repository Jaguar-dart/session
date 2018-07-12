library example.basic_auth.client;

import 'package:jaguar_resty/jaguar_resty.dart';
import 'package:http/http.dart' as http;
import '../../../example_models/lib/src/models.dart';

final base = 'http://localhost:10000';

final cookieJar = CookieJar();

main() async {
  globalClient = http.IOClient();

  await post(base)
      .path('/login')
      .interceptBefore(cookieJar.intercept)
      .urlEncodedForm({'username': 'teja', 'password': 'word'})
      .go()
      .onSuccess((_) => print("Login successful!"));

  List<Book> books = await get(base)
      .path('/book/all')
      .interceptBefore(cookieJar.intercept)
      .list(Book.fromMap);

  print(books);
}