# **12.02.Screenshot**

## **OBBJECTIVES**

* Understand how to use built-in Windows API to take screenshots of the desktop.
* Capture screenshot content in-memory so that it can be returned from your DLL without touching disk.

## **STEPS**

Part1:

* Update the code to capture a screenshot and save it in PNG format.

Part2:

* Convert the screenshot POC to an sRDI module.

  * Remove all print statements to the console.
  * Modify the code to base64 the screenshot content and return it instead of writing it to disk.
  * Test it with your Loader. You will want to base64 decode the result of the screenshot module and save it to disk in your Loader.
