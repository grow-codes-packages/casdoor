package codes.grow.packages.casdoor;

import codes.grow.packages.casdoor.core.AuthenticationException;
import codes.grow.packages.casdoor.core.CasdoorException;
import codes.grow.packages.casdoor.core.ConflictException;
import codes.grow.packages.casdoor.core.Json;
import codes.grow.packages.casdoor.core.NotFoundException;
import codes.grow.packages.casdoor.core.PermissionDeniedException;
import codes.grow.packages.casdoor.core.RateLimitException;
import codes.grow.packages.casdoor.core.TransportResponse;
import codes.grow.packages.casdoor.core.UnsupportedException;
import codes.grow.packages.casdoor.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

/** Casdoor helpers: PKCE, form bodies, token parsing and error normalization. */
public final class CasdoorFlows {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private CasdoorFlows() {}

  /**
   * A PKCE pair (RFC 7636, S256).
   *
   * @param codeVerifier verifier; keep it server-side until the code exchange
   * @param codeChallenge {@code base64url(sha256(verifier))}
   */
  public record Pkce(String codeVerifier, String codeChallenge) {
    @Override
    public String toString() {
      return "Pkce{codeChallenge=" + codeChallenge + "}";
    }
  }

  /**
   * Creates a PKCE pair.
   *
   * @return a new verifier and its challenge
   */
  public static Pkce createPkce() {
    byte[] b = new byte[48];
    RANDOM.nextBytes(b);
    String verifier = B64URL.encodeToString(b);
    return new Pkce(verifier, pkceChallenge(verifier));
  }

  /**
   * S256 challenge of a verifier.
   *
   * @param verifier the verifier
   * @return the challenge
   */
  public static String pkceChallenge(String verifier) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      return B64URL.encodeToString(md.digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Random URL-safe value for {@code state} or {@code nonce}.
   *
   * @return the value
   */
  public static String randomState() {
    byte[] b = new byte[24];
    RANDOM.nextBytes(b);
    return B64URL.encodeToString(b);
  }

  static String form(Map<String, String> pairs) {
    StringJoiner j = new StringJoiner("&");
    pairs.forEach(
        (k, v) -> {
          if (v != null) {
            j.add(enc(k) + "=" + enc(v));
          }
        });
    return j.toString();
  }

  static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }

  static void required(String op, String name, String value) {
    if (value == null || value.isBlank()) {
      throw new ValidationException(op + ": " + name + " must not be empty");
    }
  }

  static Optional<JsonNode> payload(String token) {
    String[] parts = token.split("\\.");
    if (parts.length < 2) {
      return Optional.empty();
    }
    try {
      return Optional.of(Json.tree(Base64.getUrlDecoder().decode(parts[1])));
    } catch (RuntimeException e) {
      return Optional.empty();
    }
  }

  static TokenSet tokenSet(String op, JsonNode body) {
    String access = text(body, "access_token");
    if (access == null) {
      throw new ValidationException(op + ": Casdoor returned no access_token");
    }
    long expiresIn = body.path("expires_in").asLong(0);
    return new TokenSet(
        access,
        Optional.ofNullable(text(body, "refresh_token")),
        Optional.ofNullable(text(body, "id_token")),
        Optional.ofNullable(text(body, "token_type")).orElse("Bearer"),
        expiresIn > 0 ? Optional.of(Instant.now().plusSeconds(expiresIn)) : Optional.empty());
  }

  static String text(JsonNode node, String field) {
    JsonNode v = node.get(field);
    return v != null && v.isTextual() && !v.asText().isEmpty() ? v.asText() : null;
  }

  static JsonNode body(TransportResponse r) {
    try {
      return r.jsonNode();
    } catch (RuntimeException e) {
      return Json.tree("{}".getBytes(StandardCharsets.UTF_8));
    }
  }

  /**
   * Throws the normalized error when the envelope says {@code status: error}.
   *
   * @param op operation name
   * @param body response body
   * @return the body
   */
  static JsonNode checkEnvelope(String op, JsonNode body) {
    if ("error".equals(text(body, "status"))) {
      throw envelopeError(op, Optional.ofNullable(text(body, "msg")).orElse(""));
    }
    return body;
  }

  /**
   * Maps a Casdoor {@code {"status":"error","msg":…}} envelope to a typed exception.
   *
   * @param op operation name
   * @param msg Casdoor message (redacted)
   * @return the exception
   */
  public static CasdoorException envelopeError(String op, String msg) {
    String m = msg.toLowerCase(Locale.ROOT);
    String text = op + ": " + (msg.isEmpty() ? "Casdoor returned status error" : msg);
    if (m.contains("phone number is invalid")) {
      return new ValidationException(
          text
              + " (Casdoor sends this for an empty password or code: check that the value was"
              + " loaded)");
    }
    if (m.contains("remaining chances")
        || m.contains("password or code is incorrect")
        || m.contains("please login first")
        || m.contains("access token")) {
      return new AuthenticationException(text);
    }
    if (m.contains("too many times") || m.contains("only send one code")) {
      return new RateLimitException(text);
    }
    if (m.contains("unauthorized operation") || m.contains("forbidden") || m.contains("frozen")) {
      return new PermissionDeniedException(text);
    }
    if (m.contains("already exist") || m.contains("duplicate key")) {
      return new ConflictException(text);
    }
    if (m.contains("not exist") || m.contains("doesn't exist") || m.contains("not found")) {
      return new NotFoundException(text);
    }
    if (m.contains("is not enabled") || m.contains("not supported")) {
      return new UnsupportedException(text);
    }
    return new ValidationException(text);
  }

  /**
   * Maps an OAuth {@code {"error","error_description"}} body.
   *
   * @param op operation name
   * @param error OAuth error
   * @param description description (redacted)
   * @return the exception
   */
  public static CasdoorException oauthError(String op, String error, String description) {
    String text = op + ": " + (description.isEmpty() ? error : error + ": " + description);
    return switch (error) {
      case "invalid_grant", "invalid_client", "unauthorized_client" ->
          new AuthenticationException(text);
      case "unsupported_grant_type", "unsupported_response_type" -> new UnsupportedException(text);
      default -> new ValidationException(text);
    };
  }
}
