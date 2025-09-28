// fixed_sql.java
import java.sql.*;

public class LoginRepoSafe {
  public ResultSet findByUsername(Connection connection, String username) throws Exception {
    String sql = "SELECT * FROM users WHERE username = ?";
    PreparedStatement ps = connection.prepareStatement(sql);
    ps.setString(1, username);   // parameterized -> no concatenation
    return ps.executeQuery();
  }
}
