# PE File

## [PEfunc.cpp](PEfunc.cpp)
  include file for PE.cpp
  
## [PE.cpp](PE.cpp)
  PE File info(*NT_Header*, *Optional_Header*, *Data_Directory*, *Section_Header*, *Import_Directory*, *Export_Directory*)

## [msgbox.asm](msgbox.asm)
  asm code for message box -> shellcode

## [packer.cpp](packer.cpp)
  c++, inject message box to all **.exe** file in current folder

## [packes.asm](packes.asm)
  asm, windows api, dependent code, inject message box to all **.exe** file in current folder
  
## [packer.asm](packer.asm)
  asm, windows api, independent code, self infect all **.exe** file in current folder
