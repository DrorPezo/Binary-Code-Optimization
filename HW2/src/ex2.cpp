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

typedef struct RtnCount
{
    string _name;
    ADDRINT _address;
    ADDRINT _tail;
    RTN _rtn;
    UINT64 _rtnCount;
    UINT64 _icount;
    struct RtnCount * _next;
} RTN_COUNT;

typedef struct LoopProp
{
  UINT64 _itcount;
  ADDRINT _head;
  ADDRINT _tail;
  string _loop_rtn;
  struct LoopProp *_next;
} LOOP_PROP;

RTN_COUNT * RtnList = 0;
LOOP_PROP * LoopList = 0;
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

VOID docount(UINT64 * counter)
{
    (*counter)++;
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

VOID Routine(RTN rtn, VOID *v)
{
    
    // Allocate a counter for this routine
    RTN_COUNT * rc = new RTN_COUNT;

    // The RTN goes away when the image is unloaded, so save it now
    // because we need it in the fini
    rc->_name = RTN_Name(rtn);
    rc->_address = RTN_Address(rtn);
    rc->_icount = 0;
    rc->_rtnCount = 0;

    // Add to list of routines
    rc->_next = RtnList;
    RtnList = rc;
            
    RTN_Open(rtn);
            
    // Insert a call at the entry point of a routine to increment the call count
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);
    rc->_tail = INS_Address(RTN_InsTail(rtn));
    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Insert a call to docount to increment the instruction counter for this rtn
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_icount), IARG_END);
    }

    
    RTN_Close(rtn);
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
  for(i = loops.begin(); i != loops.end(); i++) {
    LOOP_PROP * lc = new LOOP_PROP;
    target = i->first;
    for(j = i->second.begin(); j != i->second.end(); j++) {
      ip = j->first;
      count = j->second;
      //printf("0x%08jx <- 0x%08jx: %3lu\n", target, ip, count);
      lc->_head = target;
      lc->_tail = ip;
      lc->_itcount = count;
    } 
    lc->_next = LoopList;
    LoopList = lc;
  }
  for (RTN_COUNT * rc = RtnList; rc; rc = rc->_next){
    if (rc->_icount > 0){
      string rtn_name = rc->_name;
      ADDRINT head_address = rc->_address;
      ADDRINT tail_address = rc->_tail;
      //UINT64 rtn_count = rc->_rtnCount;
      //UINT64 ins_count = rc->_icount;
      for (LOOP_PROP * lp = LoopList; lp; lp = lp->_next){
        ADDRINT loop_head = lp->_head;
        ADDRINT loop_tail = lp->_tail;
        if(head_address < loop_head && loop_tail < tail_address){
          lp->_loop_rtn = rc->_name;
        }
      }
    }
  }
  printf("******* LOOPS *******\n");
  for (LOOP_PROP * lp = LoopList; lp; lp = lp->_next){
    cout << "Head address: " << showbase << hex << lp->_head <<
    " Tail address: " << showbase << hex << lp->_tail <<
    " Iteration count: " << dec << lp->_itcount << 
    " Routine: " << lp->_loop_rtn << endl;
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
  RTN_AddInstrumentFunction(Routine, 0);
  PIN_AddFiniFunction(print_results, NULL);

  /* Never returns */
  PIN_StartProgram();
    
  return 0;
}

