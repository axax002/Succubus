Succubus
=========

Log Win32 API calls to help reverse engineering.

Features
---------

* Performs standard 7-bytes inline hooking (hence not applicable for some APIs, e.g., ZwBlahBlah) under Ring3
* Uses code injecting instead of DLL injecting
* Communicates by shared memory
* All APIs are hooked to the same piece of injected byte-codes (may fall on some tricky cases, e.g., some sort of reentrance happens)
* Records params for the API call, return value/address, EBP of the caller, etc.
* Most features are implemented by C code. Must compile with mingw-gcc.
