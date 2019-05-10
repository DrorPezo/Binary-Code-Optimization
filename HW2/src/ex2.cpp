#include <stdio.h>
#include <fstream>
#include <map>
#include <iostream>
#include <string>
#include "pin.H"

std::map<ADDRINT, std::map<ADDRINT, unsigned long> > cflows;
std::map<ADDRINT, std::map<ADDRINT, unsigned long> > loops;
unsigned long cflow_count   = 0;
ofstream outFile;

/*****************************************************************************
 *                             Analysis functions                            *
 *****************************************************************************/

static void count_cflow(ADDRINT ip, ADDRINT target)
{
  cflows[target][ip]++;
  cflow_count++;
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
        ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)count_cflow, 
        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
        IARG_END
      );
      //use while loop or recursive function here with HasFallThrough until we detect all nested loops
      // if(INS_HasFallThrough(ins)) {
      //   INS_InsertPredicatedCall(
      //     ins, IPOINT_AFTER, (AFUNPTR)count_cflow, 
      //     IARG_INST_PTR, IARG_FALLTHROUGH_ADDR, 
      //     IARG_END
      //   );
      // }
      // RTN routine = INS_Rtn(ins);
      // cout << RTN_Name(routine) << endl;
    }
    std::map<ADDRINT, std::map<ADDRINT, unsigned long> >::iterator i;
    std::map<ADDRINT, unsigned long>::iterator j;
    ADDRINT ip, target;
    for(i = cflows.begin(); i != cflows.end(); i++) {
      target = i->first;
      for(j = i->second.begin(); j != i->second.end(); j++) {
        ip = j->first;
        int count = j->second;
        if(ip > target){
          loops[target][ip] = count;
        }
      } 
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
  outFile.open("loops-cnt.csv");
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

