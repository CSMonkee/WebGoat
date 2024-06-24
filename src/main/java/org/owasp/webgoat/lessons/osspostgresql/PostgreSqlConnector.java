package org.owasp.webgoat.lessons.osspostgresql;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class PostgreSqlConnector {

  private static String DRIVER_NAME = "org.postgresql.Driver";
  private static String CONNECTION_STR =
      "jdbc:postgresql://localhost:5432/test?preferQueryMode=simple";

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

  public static Connection getDriverConnection(String logfile)
      throws ClassNotFoundException, SQLException {
    Connection connection = null;
    try {
      Class.forName(DRIVER_NAME);
      connection =
          DriverManager.getConnection(CONNECTION_STR + "&" + logfile, "dummyUser", "dummyPassword");
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
