// vulnerable_java.java
import java.security.MessageDigest;

public class Vulnerable {
  // Insecure: fast unsalted MD5 for password hashing
  public static String hashPassword(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes());
    byte[] digest = md.digest();

    StringBuilder sb = new StringBuilder();
    for (byte b : digest) sb.append(String.format("%02x", b & 0xff));
    return sb.toString();
  }
}
