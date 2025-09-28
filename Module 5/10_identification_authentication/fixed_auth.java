// fixed_auth.java
public class Auth {
  public boolean login(String inputPassword, String storedHash) throws Exception {
    // Verify using secure password hasher (see PasswordHasher in cryptographic fix)
    return PasswordHasher.verifyPassword(inputPassword, storedHash);
  }
}
