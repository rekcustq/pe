# PE File

## [PEfunc.cpp](PEfunc.cpp)
  include file for PE.cpp
  
## [PE.cpp](PE.cpp)
  PE File info(*NT_Header*, *Optional_Header*, *Data_Directory*, *Section_Header*, *Import_Directory*, *Export_Directory*)

## [msgbox.asm](msgbox.asm)
  asm code for message box -> shellcode

## [pe_inject.cpp](pe_inject.cpp)
  c++, inject message box to all **.exe** file in current folder

## [pe_injector.asm](pe_injector.asm)
  asm, windows api, dependent code, inject message box to all **.exe** file in current folder
  
## [pe_inject.asm](pe_inject.asm)
  asm, windows api, independent code, self infect all **.exe** file in current folder

## [pe_uninject.cpp](pe_uninject.cpp)
  c++, remove injected code and restore file
