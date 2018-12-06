public class TestJavaClass extends Object {
    private String test_string = null;
    protected static String test_string_two = null;
    protected static String test_string_three = null;
    public static final String TEST_NAME = "StoqJavaTest";
    public TestJavaClass() {
      this(TEST_NAME);
    }
    public TestJavaClass(String test_string) {
      this.test_string = test_string;
      this.test_string_two = test_string;
      this.test_string_three = test_string_two;
    }
    public String getTest() {
      return test_string;
    }
    public static String getTestTwo() {
      return test_string_two;
    }
    public static String getTestThree() {
      return test_string_three;
    }
}