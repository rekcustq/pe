#include "PEfunc.cpp"

    HANDLE hFile;

int uninfect(const char* fName) {
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

    // 1. jump to end file and extract aoep
    int rAddr = toInt(OptionalHeader.AddressOfEntryPoint) - 16*4;
    int endFile = toInt(SectionHeader[noSec-1].PointerToRawData) + toInt(SectionHeader[noSec-1].SizeOfRawData);
    int offset = endFile-1;
    for(; ; offset--)
        if(int(buffer[offset]))
            break;
    int oep = toInt(getHex(buffer, offset-4, offset)) - toInt(OptionalHeader.ImageBase);

    offset = e_lfanew + 40;
    // 2. get aoep and replace with oep
    int aoep = toInt(getHex(buffer, offset, offset+4));
    fseek(pFile, offset, SEEK_SET);
    fwrite(&oep, 4, 1, pFile);

    offset = e_lfanew + 24 + toInt(FileHeader.SizeOfOptionalHeader) + (noSec - 1) * 40;
    // 3. decrease opcode size
    int vrsz = toInt(SectionHeader[noSec-1].SizeOfRawData) - (endFile - RVA2Offset(aoep, noSec));
    fseek(pFile, offset+16, SEEK_SET);
    fwrite(&vrsz, 4, 1, pFile);

    // 4. disable execution from characteristic
    int chrst = toInt(getHex(buffer, offset+36, offset+40));
    chrst ^= 0x20000020;
    fseek(pFile, offset+36, SEEK_SET);
    fwrite(&chrst, 4, 1, pFile);
    
    fclose(pFile);
    delete[] buffer;

    // 5. delete virus
    hFile = CreateFileA(fName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    SetFilePointer(hFile, RVA2Offset(aoep, noSec), 0, FILE_BEGIN);
    SetEndOfFile(hFile);
    CloseHandle(hFile);

    cout << "Done\n";
    return 0;
}

// g++ depacker.cpp -o depacker.exe && depacker.exe
int main(int argc, const char** argv) {
    if(argc < 2)
        return -1;

    // WIN32_FIND_DATA FindFile;
    // HANDLE hFind;

    // hFind = FindFirstFileA("*.exe", &FindFile);
    // if (hFind == INVALID_HANDLE_VALUE) {
    //     cout << "No exe file found\n" << GetLastError() << endl;
    //     return 0;
    // }
    // do
    //     uninfect(FindFile.cFileName);
    // while(FindNextFileA(hFind,&FindFile));
    uninfect(argv[1]);

    // FindClose(hFind);
    return 0;
}