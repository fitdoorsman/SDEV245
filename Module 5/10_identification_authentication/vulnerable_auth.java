// vulnerable_auth.java
public class Auth {
  public boolean login(String inputPassword, User user) {
    // insecure: comparing plaintext/stored passwords directly
    if (inputPassword.equals(user.getPassword())) {
      return true;
    }
    return false;
  }
}
