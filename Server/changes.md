We have made some changes to the Server code, in cli.py located in Server/cli/ directory. The following are the changes made to the code along with the explanations:

* Line 80 - 81: Here we have added descriptions of *bypassuac* and *getsystem* functionalities which will be displayed in the *Help* menu.
* Line 114 - 117: Here we have added code for printing task types of *bypassuac* and *getsystem*.
* Line 354 - 368: Here we have added code for loading DLL files for both *bypassuac* and *getsystem* functionalities.
* Line 517 - 537: Here we have implemented functionalities of *bypassuac* and *getsystem*. These functions take in arguments from the client side (CLI) that we as users enter, and pass them to the DLL.