package org.owasp.webgoat.lessons.ossawsredshiftjdbc42;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class RedShiftConnector {

  private static String DRIVER_NAME = "com.amazon.redshift.jdbc42.Driver";
  private static String CONNECTION_STR =
      "jdbc:redshift://redshift-cluster-1.xxxx.us-east-1.redshift.amazonaws.com/rg_tickit?preferQueryMode=simple";
  private static String access_key = "";
  private static String secret_key = "";

  public static Connection getDriverConnection() throws ClassNotFoundException, SQLException {
    Connection connection = null;
    try {
      Class.forName(DRIVER_NAME);
      connection = DriverManager.getConnection(CONNECTION_STR, "dummyUser", "dummyPassword");
    } catch (ClassNotFoundException e) {
      System.err.println("ClassNotFoundException: " + e.getMessage());
      throw e;
    } catch (SQLException sq) {
      System.err.println("SQLException: " + sq.getMessage());
      throw sq;
    }
    return connection;
  }
}
