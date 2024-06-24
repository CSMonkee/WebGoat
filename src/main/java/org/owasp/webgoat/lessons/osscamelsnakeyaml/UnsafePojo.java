package org.owasp.webgoat.lessons.osscamelsnakeyaml;

public class UnsafePojo {
  private String name;

  public UnsafePojo() {}

  public UnsafePojo(String name) {
    this.name = name;
  }

  public String getName() {
    return this.name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    UnsafePojo pojo = (UnsafePojo) o;

    return name != null ? name.equals(pojo.name) : pojo.name == null;
  }

  @Override
  public int hashCode() {
    return name != null ? name.hashCode() : 0;
  }

  @Override
  public String toString() {
    return "UnsafePojo {" + "name='" + name + '\'' + '}';
  }
}
