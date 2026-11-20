package codes.grow.packages.casdoor;

import java.time.Instant;
import java.util.Optional;

/**
 * OAuth tokens returned by sign-in, refresh and code exchange. {@link #toString()} never prints the
 * tokens.
 *
 * @param accessToken access token (JWT)
 * @param refreshToken refresh token, when granted
 * @param idToken OpenID Connect id token
 * @param tokenType token type ({@code Bearer})
 * @param expiresAt access token expiry, when known
 */
public record TokenSet(
    String accessToken,
    Optional<String> refreshToken,
    Optional<String> idToken,
    String tokenType,
    Optional<Instant> expiresAt) {

  @Override
  public String toString() {
    return "TokenSet{tokenType=" + tokenType + ", expiresAt=" + expiresAt.orElse(null) + "}";
  }
}
