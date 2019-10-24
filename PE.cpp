#include "PEfunc.cpp"

int main(int argc, const char** argv) {
    if(argc < 2)
        return -1;

    FILE * pFile = fopen (argv[1], "rb");
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
    cout << "DOS MZ header found.\nPE Header offset: 0x" << hexlfa() << "\n";

    if(!PESignature(buffer))
        return -1;

    int base = 0;
    initFileHeader(buffer);
    initOptionalHeader(buffer);
    initDataDirectory(buffer);
    int noSec = toInt(FileHeader.NumberOfSections);
    initSectionHeader(buffer, noSec);

    cout << "\n------------------------------------------------------------------------------------------------------------------------\n";
    cout << "PE signature found, Valid PE.\n";
    cout << "Address of Entry Point: 0x" << OptionalHeader.AddressOfEntryPoint << "\n";
    cout << "Check Sum: 0x" << OptionalHeader.CheckSum << "\n";
    cout << "Image Base: 0x" << OptionalHeader.ImageBase << "\n";
    cout << "File Alignment: 0x" << OptionalHeader.FileAlignment << "\n";
    cout << "Size Of Image: 0x" << OptionalHeader.SizeOfImage << "\n";

// dump sections
    cout << "\n------------------------------------------------------------------------------------------------------------------------\n";
    cout << "Number of Sections: " << noSec << "\n\n";
    cout << "Name" << setw(23) << "Characteristics" << setw(14) << "R.Address" << setw(15) << "R.Size" << setw(21) << "V.Address" << setw(16) << "V.Size\n";
    for(int i = 0; i < noSec; i++)
        cout << setw(12) << left << SectionHeader[i].Name << "0x"
          "" << setw(18) << SectionHeader[i].Characteristics << "0x"
          "" << setw(16) << SectionHeader[i].PointerToRawData << "0x"
          "" << setw(16) << SectionHeader[i].SizeOfRawData << "0x"
          "" << setw(16) << SectionHeader[i].VirtualAddress << "0x"
          "" << SectionHeader[i].VirtualSize << "\n";

//-----------------------------------------------------------------------------------------------------------------------------------
    cout << "\n------------------------------------------------------------------------------------------------------------------------\n";
// dump import
    parseImport(base, buffer, noSec);
// dump export
    parseExport(base, buffer, noSec);

    fclose(pFile);
    delete[] buffer;
    return 0;
}