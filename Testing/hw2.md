## **HW2 Test Cases**

### **Objectives**
* This file will help understand the working on test cases that we have defined.
* It will also give you a brief understanding of Base64Encode and Base64Decode Functions which you can find in readMe.md.

### **About Test Cases**
* We have imported the Bas64 Encoding and Decoding function from the the base64.h file present in the Bas64 Folder. 
* Following are the steps to create a new Google Test project and connect it to our Base64 project: 
  * In the Solution Explorer window of Visual Studio, right-click on the Solution Base64 tab.
  * Go to Add, and then select ‘New Project…’.
  * A new window will open up. On the left pane of this window, click the drop-down button of Visual C++ and select Test.
  * Click on Google Test in the middle pane of the window.
  * Give a name and folder for this test to store.
  * In the Test Project Configuration window, select the project to be tested as Base64 from the drop-down menu. Keep the default settings for the rest.
  * Click OK and this will create a new test project with its test.cpp file which is now connected to our project.

* Packages to be installed:
  * For successful running of the Google unit test, we will require a package named “Microsoft.googletest.v140.windesktop.msvcstl.static.rt-dyn” which is offered by Microsoft.
  * To install this package, follow these steps:
    * In the Solution Explorer window of Visual Studio, right-click on the Solution Base64 tab.
    * Select “Manage NuGet Packages for Solution…”
    * In the new tab that is opened, click on “Browse” and in the search bar, type in the package name mentioned above and install it.



### **How to run Test Cases**
* Option A
  * In the Visual Studio 17, you can open Test Explorer from the Test Tab.
  * Once that is done, on the test explorer tab, there is an option to run all test at once. You can use that option to run all test.
*  Option B
   *  You can also run 'run-tests.bat' file through msbuild.

### **Test Case 1**

```
TEST(Base64EncodeTest1, Encode) {
	std::string input1 = "hello world!";
	std::string encoded1 = "";

	Base64Encode(input1, &encoded1);
	EXPECT_EQ(strcmp(encoded1.c_str(), "aGVsbG8gd29ybGQh"), 0);

}
```
* This function represents the first test case. We have taken a normal string as the input.
* It takes an input string defined in "input1" variable.
* It then uses Base64Encode function to generate a Base64 hash of the string.
* "strcmp" does the job of comparing the Base64 generated hash with the original hash and returns true or false as an output.
* "EXPECT_EQ" then compares the output of "strcmp" with "0" and returns true or false as an output.

### **Test Case 2**

```
TEST(Base64EncodeTest2, Encode) {
	std::string input1 = " ";
	std::string encoded1 = "";

	Base64Encode(input1, &encoded1);
	EXPECT_EQ(strcmp(encoded1.c_str(), "IA=="), 0);

}
```
* In this test we decided to try out "space" as a string to check it output and compare it with the hash of the "space" as a string.
* It did work as aspected and the test case was successful

### **Test case 3**
```
TEST(Base64EncodeTest3, Encode) {
	std::string input1 = "hello world!";
	std::string encoded1 = "";

	Base64Encode(input1, &encoded1);
	EXPECT_EQ(strcmp(encoded1.c_str(), "fail-aGVsbG8gd29ybGQh"), -1);

}
```
* This is test case which compares two different hashes.
* The first hash is generated by the Base64Encode function which we implemented. The second hash is some random hash from web. 
* This test case was also successful

### ** Test Case 4 **

```
TEST(Base64EncodeTest4, Encode) {
	std::string input1 = "";
	std::string encoded1 = "";

	BOOL output = Base64Encode(input1, &encoded1);
	EXPECT_EQ(output, FALSE);

}
```
* In this test case we try to compare the hash of an empty string.
* Our code is defined in such a way that whenever it receives an empty string the base64Encode function returns FALSE.
* Hence we use "EXPECT_EQ" to compare the output with FALSE to test if the test case succeeded.


### **Test Case 5**

```
TEST(Base64DecodeTest1, Decode) {
	std::string input1 = "hello world!";
	std::string encoded1 = "aGVsbG8gd29ybGQh";
	std::string decoded1 = "";

	Base64Decode(encoded1, &decoded1);
	EXPECT_EQ(strcmp(decoded1.c_str(), input1.c_str()), 0);

}
```
* This is a test case for Base64Decode function. 
* Here we give a hash to the function which returns the plain text and we compare it with the original string to see if the desired outuput was produced.

### **Test Case 6**

```
TEST(Base64DecodeTest2, Decode) {
	std::string input1 = " ";
	std::string encoded1 = "IA==";
	std::string decoded1 = "";

	Base64Decode(encoded1, &decoded1);
	EXPECT_EQ(strcmp(decoded1.c_str(), input1.c_str()), 0);

}
```
* This test is to check if the decode function is able to decode the hash of a "space" as a string.
* The test case was successful because when we compared the generated decode value with "space", it returned true as an output.

### ** Test Case 7 **

```
TEST(Base64DecodeTest3, Decode) {
	std::string input1 = "hello world!";
	std::string encoded1 = "fail-aGVsbG8gd29ybGQh";
	std::string decoded1 = "";

	Base64Decode(encoded1, &decoded1);
	EXPECT_EQ(strcmp(decoded1.c_str(), input1.c_str()), !0);

}
```
* This decode test case is designed in such a way that it compared two different plain text value. 
* The first value is genereted from a hash by Base64Decode function and the second is some random plain text that we input.
  