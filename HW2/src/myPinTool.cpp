/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */


/* Profile should include:
 * 1. full path of the image file
 * 2. time stamp of the image file
 * 3. All addresses are kept in the form of relative offsets to the image base address.
 * 4. profile is kept per application.
 *
 * Time stamp of the profile file (if available). Otherwise create the file (if file does not exist).
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>



/* ================================================================== */
// Types and structures 
/* ================================================================== */
typedef struct instr_table_struct {
	UINT64 count;
	ADDRINT offset;
} instr_table_t;

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 bblCount = 0;        //number of dynamically executed basic blocks
UINT64 threadCount = 0;     //total number of threads, including main thread

instr_table_t *instrTable = NULL;
USIZE instrCountTableSize = 0;      // size of the instruction counts tables size

ADDRINT mainExeImageLowAddr = 0;
ADDRINT mainExeImageHighAddr = 0;

#define MAX_FINE_NAME_SIZE  30
int fd;
char profileFilename[MAX_FINE_NAME_SIZE];

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");


/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*
 * docount()
*/
void docount(ADDRINT addr) 
{ 
	insCount++; 

	if (addr < mainExeImageLowAddr || addr >  mainExeImageHighAddr)
		return;

	ADDRINT offset =  addr - mainExeImageLowAddr;

	UINT32 i = (offset / 2)  % instrCountTableSize;

	instrTable[i].count++;
	instrTable[i].offset = offset;
}

/*
 * Instruction()
 */
void Instruction(INS ins, void *v) 
{
    INS_InsertCall(ins, IPOINT_BEFORE, 
                   (AFUNPTR)docount, 
				   IARG_ADDRINT,
				   INS_Address(ins),
				   IARG_END);
}


/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic block, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

/*!
 * Image()           
 */ 
VOID Image(IMG img, VOID *v)
{
	if (IMG_IsMainExecutable (img)) {
		instrCountTableSize = IMG_SizeMapped (img);

		//instrTable = (instr_table_t *)calloc(instrCountTableSize, sizeof(instr_table_t));
		//if (!instrTable) {
		//	cerr << "unable to allocate " << instrCountTableSize << " bytes for the instructions profile table." << endl;
		//}
		

		mainExeImageLowAddr = IMG_LowAddress (img);
		mainExeImageHighAddr = IMG_HighAddress (img);

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
		//if (mprotect(instrTable, instrCountTableSize * sizeof(instr_table_t), PROT_READ | PROT_WRITE) == -1) {
		//	perror("mprotect");
			// exit(1);
		//}
	
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

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    threadCount++;
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    std::ostream * out = &cerr;
    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    *out <<  "===============================================" << endl;
    *out <<  "MyPinTool analysis results: " << endl;
    *out <<  "Number of instructions: " << insCount  << endl;
    *out <<  "Number of basic blocks: " << bblCount  << endl;
    *out <<  "Number of threads: " << threadCount  << endl;
    *out <<  "===============================================" << endl;

	*out << "non-zero instruction counters:" << endl;
	for (UINT32 i=0; i < instrCountTableSize; i++) {
		if (instrTable[i].count > 0) {			
			*out << "0x" << hex << instrTable[i].offset << " " << dec << instrTable[i].count << " " << RTN_FindNameByAddress (instrTable[i].offset + mainExeImageLowAddr) << endl;
		}
	}
	//munmap(instrTable, instrCountTableSize * sizeof(instr_table_t));
	close (fd);
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    if (KnobCount)
    {

        // Register function to be called to instrument traces
        //TRACE_AddInstrumentFunction(Trace, 0);

		// Register functions to be called on every instruction
		INS_AddInstrumentFunction(Instruction, 0);

        // Register function to be called for every thread before it starts running
        PIN_AddThreadStartFunction(ThreadStart, 0);

		// Register on each image load
		IMG_AddInstrumentFunction(Image, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
