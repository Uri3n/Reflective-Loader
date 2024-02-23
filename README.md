# Reflective-Loader
### An Example Reflective Loader And Implant. For educational purposes.

This repository serves as an example of how to write a reflective DLL and loader.
The purpose is to educate on the technique, not to be highly evasive.

The loader uses indirect syscalls as well as the undocumented NtCreateUserProcess to
create a sacrificial child process for payload execution.

The implant, a reflective DLL, unpacks and initializes itself when called via its
exported function, "ReflectiveStub". This DLL is initially encrypted, and stored
within the loaders .rsrc section. 
