#include <stdio.h>
#include <fstream>
#include <vector>
#include <map>
#include <iostream>
#include <string>
#include "pin.H"

std::map<ADDRINT, std::map<ADDRINT, unsigned long>> loops; //count taken edges 
ofstream outFile;
bool is_loop = FALSE;
int cnt = 0;

/*****************************************************************************
 *                             Analysis functions                            *
 *****************************************************************************/
static void count_loops(ADDRINT ip, ADDRINT target)
{
  if(ip > target){
    loops[target][ip]++;
    is_loop = TRUE;
  }
}


/*****************************************************************************
 *                         Instrumentation functions                         *
 *****************************************************************************/
static void ins_bbl(BBL bbl)
{
  // if bbl has a fall throught path - it has a branch, and may be a loop
  if(BBL_HasFallThrough(bbl)){
    for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      if(!INS_IsBranch(ins)) continue; //IMPORTANT!!! may throw an error without checking if the instruction is call or branch
      IMG img = IMG_FindByAddress(INS_Address(ins));
      if(!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return;

      INS_InsertPredicatedCall(
        ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)count_loops, 
        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
        IARG_END
      );
      if(is_loop){
          
      }
      is_loop = FALSE;
    }
  }
}

static void instrument_trace(TRACE trace, void *v)
{
  IMG img = IMG_FindByAddress(TRACE_Address(trace));
  if(!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return;
  for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
    ins_bbl(bbl);
  }
}

/*****************************************************************************
 *                               Other functions                             *
 *****************************************************************************/
static void print_results(INT32 code, void *v)
{
  ADDRINT ip, target;
  unsigned long count;
  std::map<ADDRINT, std::map<ADDRINT, unsigned long> >::iterator i;
  std::map<ADDRINT, unsigned long>::iterator j;
  printf("******* LOOPS *******\n");
  for(i = loops.begin(); i != loops.end(); i++) {
    target = i->first;
    for(j = i->second.begin(); j != i->second.end(); j++) {
      ip = j->first;
      count = j->second;
      printf("0x%08jx <- 0x%08jx: %3lu\n", target, ip, count);
    } 
  }
}

static void print_usage()
{
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
}


int main(int argc, char *argv[])
{
  PIN_InitSymbols();
  outFile.open("loop-count.csv");
  if(PIN_Init(argc,argv)) {
    print_usage();
    return 1;
  }

  TRACE_AddInstrumentFunction(instrument_trace, NULL);
  PIN_AddFiniFunction(print_results, NULL);

  /* Never returns */
  PIN_StartProgram();
    
  return 0;
}

