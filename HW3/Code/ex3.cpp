#include <stdio.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <fstream>
#include "prof.H"
#include "inst.H"
#include "pin.H"


/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobInst(KNOB_MODE_WRITEONCE,    "pintool",
    "inst", "0", "inst run");

KNOB<BOOL>   KnobProf(KNOB_MODE_WRITEONCE,    "pintool",
    "prof", "0", "prof run");

// Saving profile
// VOID Image(IMG img, VOID *v)
// {
// 	if (IMG_IsMainExecutable (img)) {
// 		instrCountTableSize = IMG_SizeMapped (img);

// 		//instrTable = (instr_table_t *)calloc(instrCountTableSize, sizeof(instr_table_t));
// 		//if (!instrTable) {
// 		//	cerr << "unable to allocate " << instrCountTableSize << " bytes for the instructions profile table." << endl;
// 		//}
		

// 		mainExeImageLowAddr = IMG_LowAddress (img);
// 		mainExeImageHighAddr = IMG_HighAddress (img);

// 		//open the profile file:
// 		//
// 		strcpy(profileFilename, "__profile.map");
		
// 		//check if pofile file exists:
// 		bool isProfileFile = false;
// 		if( access(profileFilename, F_OK ) != -1 ) {
// 			isProfileFile = true;// file exists
// 		}


// 		// open the profile file and map it to memory:
// 		//
//         fd = open(profileFilename, O_CREAT | O_RDWR, S_IRWXU);
//         if (fd == -1) {
//             perror("open");
// 			// exit (1);
// 		}

// 		/* go to the location corresponding to the last byte */
// 		if (lseek (fd, (instrCountTableSize * sizeof(instr_table_t)) - 1, SEEK_SET) == -1) {
// 		   perror ("lseek error");
// 		   // exit (1);
// 		}

// 		/* write a dummy byte at the last location */
// 		 if (write (fd, "", 1) != 1) {
// 			printf ("write error");
// 			// exit (1);
// 		 }
 
// 		cerr << "mapped addr before mmap: " << hex << instrTable << endl;

//         instrTable = (instr_table_t *)mmap(0, instrCountTableSize * sizeof(instr_table_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE , fd, 0);
// 		//instrTable = (instr_table_t *)mmap(0, instrCountTableSize * sizeof(instr_table_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
//  		if ((ADDRINT) instrTable == 0xffffffffffffffff) {
// 			perror("mmap");
// 			// exit (1)'
// 		}

// 		cerr << "mapped addr after mmap from: " << hex << instrTable << " size: " << instrCountTableSize * sizeof(instr_table_t) << endl;


// 		// set main executable permissions to both: Read, Write and Exec:
// 		//if (mprotect(instrTable, instrCountTableSize * sizeof(instr_table_t), PROT_READ | PROT_WRITE) == -1) {
// 		//	perror("mprotect");
// 			// exit(1);
// 		//}
	
// 		cerr << "content of profile map:"  << endl;
// 		for (UINT32 i=0; i < instrCountTableSize; i++) {
// 			if (instrTable[i].count > 0) {			
// 				cerr << "0x" << hex << instrTable[i].offset << " " << dec << instrTable[i].count << " " << RTN_FindNameByAddress (instrTable[i].offset + mainExeImageLowAddr) << endl;
// 			}
// 		}

// 		if (!isProfileFile)
// 		  memset(instrTable, 0, instrCountTableSize * sizeof(instr_table_t));
// 	}

// }


int main(int argc, char * argv[])
{
    PIN_InitSymbols();    
    if(PIN_Init(argc,argv)) {
        print_usage();
        return 1;
    }

    if(KnobProf){
        printf("Got Here\n");
        outFile.open("loop-count.csv");
        RTN_AddInstrumentFunction(Routine, 0);
        PIN_AddFiniFunction(print_results, NULL);
    }
    if(KnobInst){
        printf("Inst\n");
        // Register ImageLoad
	    IMG_AddInstrumentFunction(ImageLoad, 0);
        // Start the program, never returns
        PIN_StartProgramProbed();
    }

    /* Never returns */
    PIN_StartProgram();

    return 0;
}

