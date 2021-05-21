package io.vacco.gemory;

import com.esotericsoftware.jsonbeans.Json;
import io.vacco.valefar.VfAuthToken;
import io.vacco.valefar.VfAuthTokenListener;
import j8spec.junit.J8SpecRunner;
import org.junit.runner.RunWith;

import java.net.URI;
import java.util.HashMap;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;

import static j8spec.J8Spec.*;

@RunWith(J8SpecRunner.class)
public class VfAuthTokenListenerSpec {

  private static final Json json = new Json();

  static {
    it("Can process an HTTP request",  () -> {
      VfAuthTokenListener listener = new VfAuthTokenListener(ForkJoinPool.commonPool());
      Future<VfAuthToken> ft = listener.init(31982, "/oauth_callback",
          (ex, token) -> String.format("Thank you, you may close this window now: %s", json.prettyPrint(token)),
          authUri -> {
            try {
              Thread.sleep(1000);
              System.out.printf("Awaiting url callback: [%s]%n", authUri);
            } catch (Exception e) { throw new IllegalStateException(e); }
          }, "f29769ff0b4987baa6d1", "https://github.com/login/oauth/authorize",
          "ID1234", new HashMap<>());
      VfAuthToken token = ft.get();
      System.out.println("done " + token);
    });

    it("Can process an error response from a callback URI", () -> {
      URI error = new URI("http://localhost:31982/?error=access_denied&error_description=The+user+has+denied+your+application+access.&error_uri=https%3A%2F%2Fdocs.github.com%2Fapps%2Fmanaging-oauth-apps%2Ftroubleshooting-authorization-request-errors%2F%23access-denied&state=ID1234");
      System.out.println(json.prettyPrint(VfAuthTokenListener.queryParamsOf(error)));
    });
  }

}
