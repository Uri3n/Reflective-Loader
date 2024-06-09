# Reflective-Loader
### An Example Reflective Loader And Implant. For educational purposes.

This repository serves as an example of how to write a reflective DLL and loader.
The purpose is to educate on the technique, not to be highly evasive.

The loader uses indirect syscalls as well as the undocumented NtCreateUserProcess to
create a sacrificial child process for payload execution.

The implant, a reflective DLL, unpacks and initializes itself when called via its
exported function, "ReflectiveStub". This DLL is initially encrypted, and stored
within the loaders .rsrc section. 

This version of reflective DLL loading is based on the original Steven Fewer technique rather than the 
more recent "Shellcode Reflective DLL Injection" technique that has been floating around for a while now,
meaning that the reflective DLL needs to be loaded by calling the exported loader function rather than simply executing it
from the base of the memory it was loaded into.

This was tested and ran on Windows 10, and compiled with Visual Studio 2022.
