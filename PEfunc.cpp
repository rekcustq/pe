#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <locale>
#include <stdio.h>
using namespace std;
typedef unsigned char BYTE;
struct flHdr {
    string Machine;
    string NumberOfSections;
    string TimeDateStamp;
    string PointerToSymbolTable;
    string NumberOfSymbols;
    string SizeOfOptionalHeader;
    string Characteristics;
} FileHeader;
struct optHdr {
    string Magic;
    string MajorLinkerVersion;
    string MinorLinkerVersion;
    string SizeOfCode;
    string SizeOfInitializedData;
    string SizeOfUninitializedData;
    string AddressOfEntryPoint;
    string BaseOfCode;
    string BaseOfData;
    string ImageBase;
    string SectionAlignment;
    string FileAlignment;
    string MajorOperatingSystemVersion;
    string MinorOperatingSystemVersion;
    string MajorImageVersion;
    string MinorImageVersion;
    string MajorSubsystemVersion;
    string MinorSubsystemVersion;
    string Win3stringVersionValue;
    string SizeOfImage;
    string SizeOfHeaders;
    string CheckSum;
    string Subsystem;
    string DllCharacteristics;
    string SizeOfStackReserve;
    string SizeOfStackCommit;
    string SizeOfHeapReserve;
    string SizeOfHeapCommit;
    string LoaderFlags;
    string NumberOfRvaAndSizes;
} OptionalHeader;
struct datDir {
    string VirtualAddress;
    string Sz;
} DataDirectory[16];
struct secHdr {
    string Name;
    string VirtualSize;
    string VirtualAddress;
    string SizeOfRawData;
    string PointerToRawData;
    string PointerToRelocations;
    string PointerToLinenumbers;
    string NumberOfRelocations;
    string NumberOfLinenumbers;
    string Characteristics;
} SectionHeader[1000];
struct expDir {
    string Characteristics;
    string TimeDateStamp;
    string MajorVersion;
    string MinorVersion;
    string Name;
    string Base;
    string NumberOfFunctions;
    string NumberOfNames;
    string AddressOfFunctions;
    string AddressOfNames;
    string AddressOfNamesOrdinals;
} ExportDirectory;

    int e_lfanew;

string hexlfa() {
    stringstream ss;
    ss << hex << setfill('0') << setw(4) << e_lfanew;
    return ss.str();
}

string toHex(int hx) {
    int st = int(BYTE(hx));
    stringstream ss;
    ss << hex << setfill('0') << setw(2) << st;
    return ss.str();
}

string toStr(string hx) {
    stringstream ss;
    ss << hex << hx;
    return ss.str();
}

string toStr(int hx) {
    stringstream ss;
    ss << hx;
    return ss.str();
}

int toInt(string hx) {
    unsigned int x;
    stringstream ss;
    ss << hex << hx;
    ss >> x;
    return int(x);
}

int toInt(int hx) {
    unsigned int x;
    stringstream ss;
    ss << hex << toStr(hx);
    ss >> x;
    return int(x);
}

string getHex(char *buffer, int start, int finish) {
    string st = "";
    for(int i = start; i < finish; i++)
        st = toHex(buffer[i]) + st;
    return st;
}

void dumpByte(char *buffer, size_t length) {
    for(int i = 0; i < length; i++) {
        cout << toHex(buffer[i]);
        if((i+1) % 2 == 0)
            cout << " ";
        if((i+1) % 16 == 0)
            cout << "\n";
    }
}

int getMagic(char *buffer) {
    return (int(buffer[0]) == 77 && int(buffer[1]) == 90);
}

string getLfanew(char *buffer) {
    return toHex(buffer[61]) + toHex(buffer[60]);
}

int PESignature(char *buffer) {
    return (int(buffer[e_lfanew]) == 80 && int(buffer[e_lfanew+1]) == 69);
}

int initFileHeader(char *buffer) {                                 // e_lfanew + 4 -> e_lfanew + 4 + 20
    locale loc;
    int sz[7] = {2, 2, 4, 4, 4, 2, 2};
    int idx[8];
    string st[7];
    idx[0] = e_lfanew + 4;
    for(int i = 0; i < 7; i++) {
        idx[i+1] = idx[i] + sz[i];
        st[i] = getHex(buffer, idx[i], idx[i+1]);
        for(int j = 0; j < st[i].size(); j++)
            st[i][j] = toupper(st[i][j], loc);
    }

    FileHeader.Machine = st[0];
    FileHeader.NumberOfSections = st[1];
    FileHeader.TimeDateStamp = st[2];
    FileHeader.PointerToSymbolTable = st[3];
    FileHeader.NumberOfSymbols = st[4];
    FileHeader.SizeOfOptionalHeader = st[5];
    FileHeader.Characteristics = st[6];

    return e_lfanew + 4 + 20;
}

int initOptionalHeader(char *buffer) {                            // e_lfanew + 4 + 20 -> e_lfanew + 4 + 20 + 96
    locale loc;
    int sz[30] = {2, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 2, 2, 4, 4, 4, 4, 4, 4};
    int idx[31];
    string st[30];
    idx[0] = e_lfanew + 4 + 20;
    for(int i = 0; i < 30; i++) {
        idx[i+1] = idx[i] + sz[i];
        st[i] = getHex(buffer, idx[i], idx[i+1]);
        for(int j = 0; j < st[i].size(); j++)
            st[i][j] = toupper(st[i][j], loc);
    }

    OptionalHeader.Magic = st[0];
    OptionalHeader.MajorLinkerVersion = st[1];
    OptionalHeader.MinorLinkerVersion = st[2];
    OptionalHeader.SizeOfCode = st[3];
    OptionalHeader.SizeOfInitializedData = st[4];
    OptionalHeader.SizeOfUninitializedData = st[5];
    OptionalHeader.AddressOfEntryPoint = st[6];
    OptionalHeader.BaseOfCode = st[7];
    OptionalHeader.BaseOfData = st[8];
    OptionalHeader.ImageBase = st[9];
    OptionalHeader.SectionAlignment = st[10];
    OptionalHeader.FileAlignment = st[11];
    OptionalHeader.MajorOperatingSystemVersion = st[12];
    OptionalHeader.MinorOperatingSystemVersion = st[13];
    OptionalHeader.MajorImageVersion = st[14];
    OptionalHeader.MinorImageVersion = st[15];
    OptionalHeader.MajorSubsystemVersion = st[16];
    OptionalHeader.MinorSubsystemVersion = st[17];
    OptionalHeader.Win3stringVersionValue = st[18];
    OptionalHeader.SizeOfImage = st[19];
    OptionalHeader.SizeOfHeaders = st[20];
    OptionalHeader.CheckSum = st[21];
    OptionalHeader.Subsystem = st[22];
    OptionalHeader.DllCharacteristics = st[23];
    OptionalHeader.SizeOfStackReserve = st[24];
    OptionalHeader.SizeOfStackCommit = st[25];
    OptionalHeader.SizeOfHeapReserve = st[26];
    OptionalHeader.SizeOfHeapCommit = st[27];
    OptionalHeader.LoaderFlags = st[28];
    OptionalHeader.NumberOfRvaAndSizes = st[29];

    return idx[30];
}

int initDataDirectory(char *buffer) {                              // e_lfanew + 4 + 20 + 96 -> e_lfanew + 4 + 20 + FileHeader.SizeOfOptionalHeader
    int idx = e_lfanew + 4 + 20 + toInt(FileHeader.SizeOfOptionalHeader) - 128;
    string st[2];
    for(int i = 0; i < 16; i++) {
        st[0] = getHex(buffer, idx, idx+4);
        st[1] = getHex(buffer, idx+4, idx+8);
        DataDirectory[i].VirtualAddress = st[0];
        DataDirectory[i].Sz = st[1];
        idx += 8;
    }

    return idx;
}

int initSectionHeader(char *buffer, int noSec) {
    locale loc;
    int sz[10] = {8, 4, 4, 4, 4, 4, 4, 2, 2, 4};
    int idx[11];
    string st[10];
    idx[10] = e_lfanew + 4 + 20 + toInt(FileHeader.SizeOfOptionalHeader);
    for(int i = 0; i < noSec; i++) {
        idx[0] = idx[10];
        idx[1] = idx[0] + sz[0];
        st[0] = "";
        int cnt = idx[0];
        char ch;
        while(ch = buffer[cnt]) {
            st[0] += ch;
            cnt++;
        }
        for(int j = 1; j < 10; j++) {
            idx[j+1] = idx[j] + sz[j];
            st[j] = getHex(buffer, idx[j], idx[j+1]);
            for(int k = 0; k < st[j].size(); k++)
                st[j][k] = toupper(st[j][k], loc);
        }

        SectionHeader[i].Name = st[0];
        SectionHeader[i].VirtualSize = st[1];
        SectionHeader[i].VirtualAddress = st[2];
        SectionHeader[i].SizeOfRawData = st[3];
        SectionHeader[i].PointerToRawData = st[4];
        SectionHeader[i].PointerToRelocations = st[5];
        SectionHeader[i].PointerToLinenumbers = st[6];
        SectionHeader[i].NumberOfRelocations = st[7];
        SectionHeader[i].NumberOfLinenumbers = st[8];
        SectionHeader[i].Characteristics = st[9];
    }

    return idx[10];
}

int initExportDirectory(char *buffer, int offset) {
    locale loc;
    int sz[11] = {4, 4, 2, 2, 4, 4, 4, 4, 4, 4, 4};
    int idx[12];
    string st[11];
    idx[0] = offset;
    for(int i = 0; i < 11; i++) {
        idx[i+1] = idx[i] + sz[i];
        st[i] = getHex(buffer, idx[i], idx[i+1]);
        // for(int j = 0; j < st[i].size(); j++)
        //     st[i][j] = toupper(st[i][j], loc);
        while(int(st[i][0]) == 48)
            st[i].erase(st[i].begin());
        if(st[i].empty())
            st[i] = "0";
    }

    ExportDirectory.Characteristics = st[0];
    ExportDirectory.TimeDateStamp = st[1];
    ExportDirectory.MajorVersion = st[2];
    ExportDirectory.MinorVersion = st[3];
    ExportDirectory.Name = st[4];
    ExportDirectory.Base = st[5];
    ExportDirectory.NumberOfFunctions = st[6];
    ExportDirectory.NumberOfNames = st[7];
    ExportDirectory.AddressOfFunctions = st[8];
    ExportDirectory.AddressOfNames = st[9];
    ExportDirectory.AddressOfNamesOrdinals = st[10];

    return idx[11];
}

int RVA2Offset(int rva, int noSec) {
    for(int i = 0; i < noSec; i++)
        if(toInt(SectionHeader[i].VirtualAddress) <= rva && rva < (toInt(SectionHeader[i].VirtualAddress) + toInt(SectionHeader[i].VirtualSize))) {
            rva -= toInt(SectionHeader[i].VirtualAddress);
            rva += toInt(SectionHeader[i].PointerToRawData);

            return rva;
        }

    return -1;
}

int offset2RVA(int offset, int noSec) {
    for(int i = 0; i < noSec; i++)
        if(toInt(SectionHeader[i].PointerToRawData) < offset && offset <= (toInt(SectionHeader[i].PointerToRawData) + toInt(SectionHeader[i].SizeOfRawData))) {
            offset -= toInt(SectionHeader[i].PointerToRawData);
            offset += toInt(SectionHeader[i].VirtualAddress);

            return offset;
        }

    return -1;
}

void parseExport(int base, char *buffer, int noSec) {
    cout << "Parsing Exports...\n\n";

    int offset = base + RVA2Offset(toInt(DataDirectory[0].VirtualAddress), noSec);
    if(offset == -1) {
        cout << "No Exports Found!\n\n";
        cout << "==================================================\n\n";
        return;
    }

    offset = initExportDirectory(buffer, offset);

    cout << setw(36) << left << "Name (Internal):" << "0x" << hex << ExportDirectory.Name << '\n';
    cout << setw(36) << left << "Version:" << ExportDirectory.MajorVersion << "." << ExportDirectory.MinorVersion << '\n';
    cout << setw(36) << left << "Address Array Base:" << dec << ExportDirectory.Base << '\n';
    cout << setw(36) << left << "Functions Exported:" << dec << ExportDirectory.NumberOfFunctions << '\n';
    cout << setw(36) << left << "Named:" << dec << ExportDirectory.NumberOfNames << '\n';

    int noFunc = toInt(ExportDirectory.NumberOfFunctions);
    int noName = toInt(ExportDirectory.NumberOfNames);
    bool namedCheck[noFunc];
    for(int i = 0; i < noFunc; i++)
        namedCheck[i] = 0;

    cout << "Named Exports - " << dec << ExportDirectory.NumberOfNames << " :\n\n";
    for(int i = 0; i < noName; i++) {
        int funcRVA = toInt(getHex(buffer, offset+noName*0+i*4, offset+noName*0+i*4+4));
        int nameRVA = toInt(getHex(buffer, offset+noName*4+i*4, offset+noName*4+i*4+4));
        int nameOrd = toInt(getHex(buffer, offset+noName*8+i*2, offset+noName*8+i*2+2));
        char ch;
        string name = "";
        while(ch = buffer[base + RVA2Offset(nameRVA, noSec)]) {
            name += ch;
            nameRVA++;
        }
        namedCheck[nameOrd] = 1;
        cout << "0x" << hex << setw(10) << left << funcRVA << setw(80) << name << "0x" << nameOrd << endl;
    }

    if(noFunc > noName) {
        cout << "\nOrdinal Exports - " << dec << noFunc-noName << " :\n\n";
        for(int i = 0; i < noFunc; i++)
            if(!namedCheck[i]) {
                int funcOffset = base + RVA2Offset(toInt(getHex(buffer, offset+i*4, offset+i*4+4)), noSec);
                cout << "0x" << setw(10) << left << getHex(buffer, funcOffset+i*4, funcOffset+i*4+4) << "0x" << hex << setw(10) << left << i << "\n";
            }
    }

    cout << "\nExports Parsing Complete!\n\n";
quitExport:
    cout << "==================================================\n\n";
}

void parseImport(int base, char *buffer, int noSec) {
    cout << "Parsing Imports...\n\n";

    int offset = base + RVA2Offset(toInt(DataDirectory[1].VirtualAddress), noSec);
    if(offset == -1) {
        cout << "No Imports Found!\n\n";
        cout << "==================================================\n\n";
        return;
    }

    for(int i = 0; ; i++) {
        string OriginalFirstThunk = getHex(buffer, offset, offset+4);
        while(int(OriginalFirstThunk[0]) == 48)
            OriginalFirstThunk.erase(OriginalFirstThunk.begin());
        int nameRVA = toInt(getHex(buffer, offset+12, offset+16));
        string FirstThunk = getHex(buffer, offset+16, offset+20);
        if(!toInt(FirstThunk))
            break;
        char ch;
        string name = "";
        while(ch = buffer[base + RVA2Offset(nameRVA, noSec)]) {
            name += ch;
            nameRVA++;
        }
        while(int(OriginalFirstThunk[0]) == 48)
            OriginalFirstThunk.erase(OriginalFirstThunk.begin());
        if(OriginalFirstThunk.empty())
            OriginalFirstThunk = "0";
        while(int(FirstThunk[0]) == 48)
            FirstThunk.erase(FirstThunk.begin());
        if(FirstThunk.empty())
            FirstThunk = "0";

        cout << setw(7) << "Index:" << setw(10) << left << hex << i << ""
          "" << setw(6) << "Name:" << name << "\n\n";
        cout << setw(36) << "Original First Thunk RVA:" << "0x" << OriginalFirstThunk << "\n";
        cout << setw(36) << "First Thunk RVA:"<<"0x" << FirstThunk << "\n";
        cout << "Imported List:\n";
        int thnkData;// = toInt(OriginalFirstThunk) == 0 ? toInt(FirstThunk) : toInt(OriginalFirstThunk);
        int cnt = 0;
        while((thnkData = base + RVA2Offset(toInt(FirstThunk)+cnt*4, noSec)) > 0) {
            if(thnkData > 0x80000000) {
                cout << "\tOrdinal: 0x" << thnkData << endl;
                cnt++;
                continue;
            }
            int func = base + RVA2Offset(toInt(getHex(buffer, thnkData, thnkData+4)), noSec) + 2;
            if(func == 1)
                break;
            cout << "\t";
            while(ch = buffer[func]) {
                cout << ch;
                func++;
            }
            cout << endl;
            cnt++;
        }

        cout << setw(7) << "\nEnd Index:" << setw(10) << i << "\n\n";

        offset += 20;
    }

    cout << "\nImports Parsing Complete!\n\n";
quitImport:
    cout << "==================================================\n\n";
}