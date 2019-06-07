#include <stdio.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector> 
#include "prof.H"
#include "inst.H"
#include "pin.H"
#define MAX_FINE_NAME_SIZE  30

ifstream inputFile;
char profileFilename[MAX_FINE_NAME_SIZE];
int fd;

/* ================================================================== */
// Types and structures 
/* ================================================================== */
typedef struct instr_table_struct {
	UINT64 count;
	ADDRINT offset;
} instr_table_t;

typedef struct hot_rtn_data{
    ADDRINT addr;
    UINT64 cnt;
    char name[MAX_FINE_NAME_SIZE];
} hot_rtn_data_t;

vector<hot_rtn_data_t*> hot_rtns;
/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobInst(KNOB_MODE_WRITEONCE,    "pintool",
    "inst", "0", "inst run");

KNOB<BOOL>   KnobProf(KNOB_MODE_WRITEONCE,    "pintool",
    "prof", "0", "prof run");

//Saving profile
VOID Image(IMG img, VOID *v)
{
	if (IMG_IsMainExecutable (img)) {
		USIZE instrCountTableSize = IMG_SizeMapped (img);
        
		instr_table_t* instrTable = (instr_table_t *)calloc(instrCountTableSize, sizeof(instr_table_t));
		if (!instrTable) {
			cerr << "unable to allocate " << instrCountTableSize << " bytes for the instructions profile table." << endl;
		}
		
        
		ADDRINT mainExeImageLowAddr = IMG_LowAddress (img);
        
		// ADDRINT mainExeImageHighAddr = IMG_HighAddress (img);

		//open the profile file:
		//
		strcpy(profileFilename, "__profile.map");

		//check if pofile file exists:
		bool isProfileFile = false;
		if( access(profileFilename, F_OK ) != -1 ) {
			isProfileFile = true;// file exists
		}


		// open the profile file and map it to memory:
		//
        fd = open(profileFilename, O_CREAT | O_RDWR, S_IRWXU);
        if (fd == -1) {
            perror("open");
			// exit (1);
		}

		/* go to the location corresponding to the last byte */
		if (lseek (fd, (instrCountTableSize * sizeof(instr_table_t)) - 1, SEEK_SET) == -1) {
		   perror ("lseek error");
		   // exit (1);
		}

		/* write a dummy byte at the last location */
		 if (write (fd, "", 1) != 1) {
			printf ("write error");
			// exit (1);
		 }
 
		cerr << "mapped addr before mmap: " << hex << instrTable << endl;

        instrTable = (instr_table_t *)mmap(0, instrCountTableSize * sizeof(instr_table_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE , fd, 0);
		//instrTable = (instr_table_t *)mmap(0, instrCountTableSize * sizeof(instr_table_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 		if ((ADDRINT) instrTable == 0xffffffffffffffff) {
			perror("mmap");
			// exit (1)'
		}

		cerr << "mapped addr after mmap from: " << hex << instrTable << " size: " << instrCountTableSize * sizeof(instr_table_t) << endl;


		// set main executable permissions to both: Read, Write and Exec:
		if (mprotect(instrTable, instrCountTableSize * sizeof(instr_table_t), PROT_READ | PROT_WRITE) == -1) {
			perror("mprotect");
			exit(1);
		}
	
		cerr << "content of profile map:"  << endl;
		for (UINT32 i=0; i < instrCountTableSize; i++) {
			if (instrTable[i].count > 0) {			
				cerr << "0x" << hex << instrTable[i].offset << " " << dec << instrTable[i].count << " " << RTN_FindNameByAddress (instrTable[i].offset + mainExeImageLowAddr) << endl;
			}
		}

		if (!isProfileFile)
		  memset(instrTable, 0, instrCountTableSize * sizeof(instr_table_t));
	}

}

bool exist(hot_rtn_data_t* rtn){
    for (std::vector<hot_rtn_data_t*>::iterator it = hot_rtns.begin() ; it != hot_rtns.end(); ++it){
        if( ((*it)->addr == rtn->addr)){ 
            return true;
        }
    }
    return false;
}

int main(int argc, char * argv[])
{
    PIN_InitSymbols();    
    if(PIN_Init(argc,argv)) {
        print_usage();
        return 1;
    }

    if(KnobProf){
        outFile.open("loop-count.csv");
        RTN_AddInstrumentFunction(Routine, 0);
        PIN_AddFiniFunction(print_results, NULL);
        // IMG_AddInstrumentFunction(Image, 0);
    }
    if(KnobInst){
        printf("Inst\n");
        string line;
        char *s;
        inputFile.open("loop-count.csv");
        while (getline (inputFile,line))
        {
            char* l = const_cast<char*> (line.c_str());             
            s = strtok(l, ",");  
            vector<char*> loop;
            hot_rtn_data_t *rtn_data = (hot_rtn_data_t*)malloc(sizeof(hot_rtn_data_t));
            int cnt = 0;
            int cnt_seen;
            char* rtn_name;
            ADDRINT rtn_address;
            while (s){
                if(cnt == 1){
                    cnt_seen = atoi(s);
                    //cout << cnt_seen << " ";
                    rtn_data->cnt = cnt_seen;
                }

                if(cnt == 5){
                    rtn_name = s;
                    //cout << rtn_name << " ";
                    //rtn_data->name = rtn_name;
                    strcpy(rtn_data->name, rtn_name);
                }

                if(cnt == 6){
                    rtn_address = (long)strtol(s, NULL, 0);
                    //cout << rtn_address;
                    rtn_data->addr = rtn_address;
                }
                s = strtok(NULL, ",");
                cnt++;        
            }
            //cout << endl;
            if(!exist(rtn_data)){
                hot_rtns.push_back(rtn_data);
            }
            if(hot_rtns.size() == 10){
                break;
            }
            //cout << hot_rtns.size() << endl;
        }
        for (std::vector<hot_rtn_data_t*>::iterator it = hot_rtns.begin() ; it != hot_rtns.end(); ++it){
            cout << (*it)->name << endl;
            cout << showbase << dec << (*it)->cnt << " " << showbase << hex << (*it)->addr << " " << endl;  
        }
        // Register ImageLoad
	    // IMG_AddInstrumentFunction(ImageLoad, 0);
        // Start the program, never returns
        // PIN_StartProgramProbed();
        inputFile.close();
    }

    /* Never returns */
    PIN_StartProgram();

    return 0;
}

