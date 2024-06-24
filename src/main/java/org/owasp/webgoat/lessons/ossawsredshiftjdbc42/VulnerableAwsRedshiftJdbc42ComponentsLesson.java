/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.ossawsredshiftjdbc42;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable-awsredshiftjdbc42.hint"})
public class VulnerableAwsRedshiftJdbc42ComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(VulnerableAwsRedshiftJdbc42ComponentsLesson.class.getName());

  @PostMapping("/VulnerableAwsRedshiftJdbc42ComponentsLesson/CVE-2024-32888")
  public @ResponseBody AttackResult index(
      @RequestParam("count") Integer count, @RequestParam("userId") String userId) {
    //	https://security.snyk.io/vuln/SNYK-JAVA-COMAMAZONREDSHIFT-6841702 - CVE-2024-32888
    log.info(
        "Received a request for VulnerableAwsRedshiftJdbc42ComponentsLesson/ version: {}", count);

    String queryString = "SELECT * From user_data WHERE Login_Count = ? and userid= ?";
    try (Connection connection = RedShiftConnector.getDriverConnection()) {
      PreparedStatement query = connection.prepareStatement(queryString);
      query.setInt(1, count);
      query.setString(2, userId);

      try {
        ResultSet results = query.executeQuery();

        if ((results != null) && (results.first() == true)) {
          ResultSetMetaData resultsMetaData = results.getMetaData();
          StringBuilder output = new StringBuilder();

          output.append(writeTable(results, resultsMetaData));
          results.last();

          // If they get back more than one user they succeeded
          if (results.getRow() > 1 && count == -1) {
            return success(this)
                .feedback("awsredshiftjdbc42=injection.success")
                .output(
                    "Your query was: "
                        + queryString.replace("?", count.toString()).replace("?", userId))
                .feedbackArgs(output.toString())
                .build();
          } else {
            return failed(this)
                .output(
                    output.toString()
                        + "<br> Your query was: "
                        + queryString.replace("?", count.toString()).replace("?", userId))
                .build();
          }

        } else {
          return failed(this)
              .feedback("awsredshiftjdbc42=injection.no.results")
              .output(
                  "Your query was: "
                      + queryString.replace("?", count.toString()).replace("?", userId))
              .build();
        }
      } catch (SQLException sqle) {

        return failed(this)
            .output(
                sqle.getMessage()
                    + "<br> Your query was: "
                    + queryString.replace("?", count.toString()).replace("?", userId))
            .build();
      }

    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-awsredshiftjdbc42-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-awsredshiftjdbc42-components.close")
          .output(ex.getMessage())
          .build();
    }

    //		return
    // failed(this).feedback("vulnerable-awsredshiftjdbc42-components.fromXML").feedbackArgs(count,userId).build();
  }

  private static String writeTable(ResultSet results, ResultSetMetaData resultsMetaData)
      throws SQLException {
    int numColumns = resultsMetaData.getColumnCount();
    results.beforeFirst();
    StringBuilder t = new StringBuilder();
    t.append("<p>");

    if (results.next()) {
      for (int i = 1; i < (numColumns + 1); i++) {
        t.append(resultsMetaData.getColumnName(i));
        t.append(", ");
      }

      t.append("<br />");
      results.beforeFirst();

      while (results.next()) {

        for (int i = 1; i < (numColumns + 1); i++) {
          t.append(results.getString(i));
          t.append(", ");
        }

        t.append("<br />");
      }

    } else {
      t.append("Query Successful; however no data was returned from this query.");
    }

    t.append("</p>");
    return (t.toString());
  }

  public static void main(String[] args) {

    Logger log =
        LoggerFactory.getLogger(VulnerableAwsRedshiftJdbc42ComponentsLesson.class.getName());

    com.amazon.redshift.jdbc42.DataSource ds = new com.amazon.redshift.jdbc42.DataSource();

    try {
      Connection con = RedShiftConnector.getDriverConnection();
      log.info("Copnnection Estrablished -->  {}", con.isClosed());
      System.out.println("Copnnection Estrablished --> " + con.isClosed());
    } catch (SQLException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (ClassNotFoundException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }
}
