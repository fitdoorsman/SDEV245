// vulnerable_sql.java
import java.sql.*;

public class LoginRepo {
  public ResultSet findByUsername(Connection connection, String username) throws Exception {
    String query = "SELECT * FROM users WHERE username = '" + username + "'";
    Statement stmt = connection.createStatement();
    return stmt.executeQuery(query);
  }
}
