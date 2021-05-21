package io.vacco.valefar;

import com.sun.net.httpserver.*;

import java.awt.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.Collectors;

import static io.vacco.valefar.VfConstants.*;
import static java.lang.String.format;

public class VfAuthTokenListener {

  public static final String CODE = "code";
  private final ExecutorService executor;

  public VfAuthTokenListener(ExecutorService executor) { this.executor = executor; }

  public static Map<String, String> queryParamsOf(URI uri) {
    if (uri.getQuery() == null) return Collections.emptyMap();
    return Arrays.stream(uri.getQuery().split("&"))
        .map(kv -> kv.split("="))
        .collect(Collectors.toMap(arr -> arr[0], arr -> URLDecoder.decode(arr[1], StandardCharsets.UTF_8)));
  }

  public Future<VfAuthToken> init(int localPort, String localContext,
                                  BiFunction<HttpExchange, VfAuthToken, String> localResponseFn,
                                  Consumer<URI> localAwaitCallback,
                                  String clientId, String authorizeUri, String state,
                                  Map<String, String> additionalParameters) throws URISyntaxException, IOException {

    additionalParameters.put(CLIENT_ID, clientId);
    additionalParameters.put(REDIRECT_URI, format("http://localhost:%d%s", localPort, localContext));
    additionalParameters.put(STATE, state);

    if (GraphicsEnvironment.isHeadless()) { throw new IllegalStateException("Not running on a client platform"); }
    if (!localContext.startsWith("/")) {
      throw new IllegalStateException(format("Local listener context does not start with '/': [%s]", localContext));
    }

    String paramsStr = additionalParameters.entrySet().stream()
        .map(e -> format("%s=%s", e.getKey(), URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)))
        .collect(Collectors.joining("&"));
    URI target = new URI(format("%s?%s", authorizeUri, paramsStr));
    VfAuthToken authToken = new VfAuthToken();

    Desktop.getDesktop().browse(target);

    return executor.submit(() -> {
      HttpServer httpServer = HttpServer.create(new InetSocketAddress(localPort), 0);
      httpServer.createContext(localContext, ex -> {
        Map<String, String> uriParams = queryParamsOf(ex.getRequestURI());
        String state0 = uriParams.get(STATE);

        if (!state.equals(state0)) {
          throw new IllegalStateException(format("Response state mismatch: [%s], [%s]", state, state0));
        }
        authToken.code = uriParams.get(CODE);
        authToken.state = state0;
        authToken.additionalParams = uriParams;

        String response = localResponseFn.apply(ex, authToken);
        OutputStream os = ex.getResponseBody();

        ex.sendResponseHeaders(200, response.getBytes().length);
        os.write(response.getBytes());
        os.close();
      });

      httpServer.setExecutor(null);
      httpServer.start();
      while (authToken.code == null) { localAwaitCallback.accept(target); }
      httpServer.stop(0);

      return authToken;
    });
  }

}
