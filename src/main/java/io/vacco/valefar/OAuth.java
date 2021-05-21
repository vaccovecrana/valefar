package io.vacco.valefar;

import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OAuth {
  private final String category;
  private final CloseableHttpClient http;
  private final String clientID;
  private final String redirectURL, authorizeURL, accessTokenURL;
  private final String scopes;
  private String clientSecret;

  public OAuth(String category, String clientID, String redirectURL, String authorizeURL, String accessTokenURL, String scopes,
               int connectionPoolSize) {
    this.category = category;
    this.clientID = clientID;
    this.redirectURL = redirectURL;
    this.authorizeURL = authorizeURL;
    this.accessTokenURL = accessTokenURL;
    this.scopes = scopes;

    PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
    connectionManager.setMaxTotal(connectionPoolSize);
    connectionManager.setDefaultMaxPerRoute(connectionPoolSize);
    http = HttpClients.custom().setConnectionManager(connectionManager).build();
  }

  public OAuth(String category, String clientID, String redirectURL, String authorizeURL, String accessTokenURL, String scopes,
               CloseableHttpClient http) {
    this.category = category;
    this.clientID = clientID;
    this.redirectURL = redirectURL;
    this.authorizeURL = authorizeURL;
    this.accessTokenURL = accessTokenURL;
    this.scopes = scopes;
    this.http = http;
  }

  public boolean authorize(Token token) throws IOException {
    if (token.accessToken != null) return false;
    obtainAccessToken(token, authorizeURL //
        + "?client_id=" + URLEncoder.encode(clientID, "UTF-8") //
        + "&response_type=code" //
        + "&redirect_uri=" + URLEncoder.encode(redirectURL, "UTF-8") //
        + "&scope=" + URLEncoder.encode(scopes, "UTF-8"));
    return true;
  }

  protected void obtainAccessToken(Token token, String url) throws IOException {
    if (clientSecret == null) throw new UnsupportedOperationException();

    if (INFO) info(category, "Visit this URL, allow access, and paste the new URL:\n" + url);
    try {
      Desktop.getDesktop().browse(new URI(url));
    } catch (Exception ignored) {
    }
    String authorizationCode = new BufferedReader(new InputStreamReader(System.in)).readLine();
    if (authorizationCode.contains("code=")) {
      Pattern pattern = Pattern.compile("code=([^&]+)&?");
      Matcher matcher = pattern.matcher(authorizationCode);
      if (matcher.find()) authorizationCode = matcher.group(1);
    }

    if (TRACE) trace(category, "Requesting access token.");
    JsonValue json = post(accessTokenURL, //
        "code=" + URLEncoder.encode(authorizationCode, "UTF-8") //
            + "&redirect_uri=" + URLEncoder.encode(redirectURL, "UTF-8") //
            + "&client_id=" + URLEncoder.encode(clientID, "UTF-8") //
            + "&client_secret=" + URLEncoder.encode(clientSecret, "UTF-8") //
            + "&grant_type=authorization_code");
    try {
      token.refreshToken = json.getString("refresh_token", null);
      token.accessToken = json.getString("access_token");
      token.expirationMillis = System.currentTimeMillis() + json.getInt("expires_in", Integer.MAX_VALUE) * 1000;
    } catch (Throwable ex) {
      throw new IOException("Invalid access token response" + (json != null ? ": " + json : "."), ex);
    }

    if (INFO) info(category, "Access token stored.");
  }

  public boolean refreshAccessToken(Token token) {
    if (!token.isExpired()) return false;
    if (TRACE) trace(category, "Refreshing access token.");

    if (token.refreshToken == null) {
      if (ERROR) error(category, "Refresh token is missing.");
      return false;
    }

    JsonValue json = null;
    try {
      json = post(accessTokenURL, //
          "refresh_token=" + URLEncoder.encode(token.refreshToken, "UTF-8") //
              + "&client_id=" + URLEncoder.encode(clientID, "UTF-8") //
              + "&client_secret=" + URLEncoder.encode(clientSecret, "UTF-8") //
              + "&grant_type=refresh_token");
      token.accessToken = json.getString("access_token");
      token.expirationMillis = System.currentTimeMillis() + json.getInt("expires_in") * 1000;
      if (DEBUG) debug(category, "Access token refreshed.");
      return true;
    } catch (Throwable ex) {
      if (ERROR) error(category, "Error refreshing access token" + (json != null ? ": " + json : "."), ex);
      return false;
    }
  }

  private JsonValue post(String url, String postBody) throws IOException {
    HttpPost request = new HttpPost(url);
    request.setEntity(new StringEntity(postBody));
    request.setHeader("Content-Type", "application/x-www-form-urlencoded");

    HttpEntity entity = null;
    CloseableHttpResponse response = null;
    try {
      response = http.execute(request);
      String body = "";
      entity = response.getEntity();
      if (entity != null) {
        Scanner scanner = null;
        try {
          scanner = new Scanner(entity.getContent(), "UTF-8").useDelimiter("\\A");
          if (scanner.hasNext()) body = scanner.next().trim();
        } finally {
          if (scanner != null) {
            try {
              scanner.close();
            } catch (Throwable ignored) {
            }
          }
        }
      }

      int status = response.getStatusLine().getStatusCode();
      if (status < 200 || status >= 300)
        throw new IOException(response.getStatusLine().toString() + (body.length() > 0 ? "\n" + body : ""));
      return new JsonReader().parse(body);
    } finally {
      if (entity != null) EntityUtils.consumeQuietly(entity);
      if (response != null) {
        try {
          response.close();
        } catch (Throwable ignored) {
        }
      }
    }
  }

  public String getClientID() {
    return clientID;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getRedirectURL() {
    return redirectURL;
  }

  public String getAuthorizeURL() {
    return authorizeURL;
  }

  public String getAccessTokenURL() {
    return accessTokenURL;
  }

  public String getScopes() {
    return scopes;
  }

}
