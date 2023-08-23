# **10.01.GetSystem**

## **OBJECTIVES**

* Understanding how to escalate privileges to gain SYSTEM access.

## **STEPS**

You will need to build your **Debug EXE** and run it as an **Administrator** during testing.

If you want, you can run Visual Studio as an Administrator to make debugging easier.

Lab Docs: should include part1.

Part 1:

Fix the Getsystem code.

Testing:

* Build the Debug EXE.
* Run it as an Administrator.
* Validate it is in High Integrity using `whoami /groups |findstr SYSTEM`
* Modify the code so you can pass args.

--

Part2

This can be done during class if you finish part 1.

Create the sRDI-Getsystem project.

New Project in Visual Studio.

Use the Mkdir DLL as a template.

Release x64 build configuration:

* General -> Configuration Type : Dynamic Library (.dll)
* C/C++ -> Code Generation Runtime Library: `Multi-Threaded /MT`
* Linker -> Debugging -> Generate Debug Info: No

Once you are done, you can complete the ExecuteW function and test the module using the Loader you used with MkDir, ListPrivs and SetPriv.
Update main to call ExecuteW and pass in the command you want to execute in high integrity. The MkDir code can be used an example.

The sRDI version of this module will be used in the homework.

```cpp
LPWSTR ExecuteW(LPCWSTR lpUserdata, DWORD nUserdataLen)
```

input: [cmd /args] to execute

output:

"1" when the change was been made.
NULL when there is any errors.

## **REFERENCES**

* [Getsystem - PIPE](https://blog.xpnsec.com/becoming-system/)