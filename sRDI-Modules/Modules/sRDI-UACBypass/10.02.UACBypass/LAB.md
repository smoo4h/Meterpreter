# **10.02.UACBypass**

## **OBJECTIVES**

* Understanding UAC and how to bypass it.
* Add registry values in code.

## **STEPS**

Fix the BypassUAC code.

BypassUAC - spawn a process in high integrity using fodhelper UAC bypass.

Testing:

* Build the Debug EXE.
* Run it as an Administrator.
* Validate it is in High Integrity using `whoami /groups |findstr High`

--

Part2

This can be done during class if you finish part 1.

Once you are done, you can complete the ExecuteW function and test the module using the Loader you used with MkDir, ListPrivs and SetPriv.
Update main to call ExecuteW and pass in the command you want to execute in high integrity. The MkDir code can be used an example.

The sRDI version of this module will be used in the next homework.

```cpp
LPWSTR ExecuteW(LPCWSTR lpUserdata, DWORD nUserdataLen)
```

input: [cmd /args] to execute

output:

"1" when the change was been made.
NULL when there is any errors.

## **REFERENCES**

* [BypassUAC - fodhelper](https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/)