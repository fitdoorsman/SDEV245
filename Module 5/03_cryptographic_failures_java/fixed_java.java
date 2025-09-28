// fixed_java.java
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class PasswordHasher {
  private static final int ITERATIONS = 120_000;
  private static final int KEY_LENGTH = 256; // bits
  private static final SecureRandom RNG = new SecureRandom();

  public static String hashPassword(String password) throws Exception {
    byte[] salt = new byte[16];
    RNG.nextBytes(salt);

    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
    byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                                  .generateSecret(spec).getEncoded();

    return "pbkdf2$" + ITERATIONS + "$" +
           Base64.getEncoder().encodeToString(salt) + "$" +
           Base64.getEncoder().encodeToString(hash);
  }

  public static boolean verifyPassword(String password, String stored) throws Exception {
    String[] parts = stored.split("\\$");
    if (parts.length != 4 || !parts[0].equals("pbkdf2")) return false;

    int iters = Integer.parseInt(parts[1]);
    byte[] salt = Base64.getDecoder().decode(parts[2]);
    byte[] expected = Base64.getDecoder().decode(parts[3]);

    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iters, expected.length * 8);
    byte[] actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                                    .generateSecret(spec).getEncoded();

    int diff = 0;
    for (int i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff == 0;
  }
}
