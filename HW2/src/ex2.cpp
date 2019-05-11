#include <stdio.h>
#include <fstream>
#include <vector>
#include <map>
#include <iostream>
#include <string>
#include "pin.H"

std::map<ADDRINT, std::map<ADDRINT, unsigned long>> countSeen; 
std::map<ADDRINT,unsigned long> loopInvoked; 
ofstream outFile;
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
  UINT _invkcount;
  ADDRINT _head;
  ADDRINT _tail;
  struct RtnCount *_routine;
  struct LoopProp *_next;
} LOOP_PROP;

RTN_COUNT * RtnList = 0;
LOOP_PROP * LoopList = 0;
/*****************************************************************************
 *                             Analysis functions                            *
 *****************************************************************************/
static void count_loops(ADDRINT ip, ADDRINT target, ADDRINT fall_through, BOOL branch_taken)
{
  if(branch_taken){
    // iterate the loop
    if(target < fall_through){
      countSeen[target][fall_through]++;
    }
  }
  else{
    loopInvoked[target]++;
  }
}

VOID docount(UINT64 * counter)
{
    (*counter)++;
}


/*****************************************************************************
 *                         Instrumentation functions                         *
 *****************************************************************************/
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
    rc->_rtn = rtn;

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
      if(!INS_IsDirectBranch(ins) || !INS_HasFallThrough(ins)) continue; 
      IMG img = IMG_FindByAddress(INS_Address(ins));
      if(!IMG_Valid(img)) return;

      INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)count_loops, 
        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, IARG_BRANCH_TAKEN, 
        IARG_END
      );
    }
    rc->_icount = RTN_NumIns(rtn);
    RTN_Close(rtn);
}

/*****************************************************************************
 *                               Other functions                             *
 *****************************************************************************/
static void print_results(INT32 code, void *v)
{
  ADDRINT ft, target;
  unsigned long count;
  std::map<ADDRINT, std::map<ADDRINT, unsigned long> >::iterator i;
  std::map<ADDRINT, unsigned long>::iterator j;
  for(i = countSeen.begin(); i != countSeen.end(); i++) {
    LOOP_PROP * lc = new LOOP_PROP;
    target = i->first;
    for(j = i->second.begin(); j != i->second.end(); j++) {
      ft = j->first;
      count = j->second;
      lc->_head = target;
      lc->_tail = ft;
      lc->_itcount = count;
    } 

    lc->_invkcount = loopInvoked[target];
 
    lc->_next = LoopList;
    LoopList = lc;
  }
  for (RTN_COUNT * rc = RtnList; rc; rc = rc->_next){
    if (rc->_icount > 0){
      string rtn_name = rc->_name;
      ADDRINT head_address = rc->_address;
      ADDRINT tail_address = rc->_tail;
      for (LOOP_PROP * lp = LoopList; lp; lp = lp->_next){
        ADDRINT loop_head = lp->_head;
        ADDRINT loop_tail = lp->_tail;
        if(head_address < loop_head && loop_tail < tail_address){
          lp->_routine = rc;
        }
      }
    }
  }
  int loop_ctr = 1;
  cout << "******* LOOPS *******" << endl;
  for (LOOP_PROP * lp = LoopList; lp; lp = lp->_next){
    cout << "******* LOOP " << loop_ctr << "*******" << endl;
    cout << "Head address: " << showbase << hex << lp->_head << endl;
    cout << "Tail address: " << showbase << hex << lp->_tail << endl;
    cout << "Count Seen: " << dec << lp->_itcount << endl;
    cout << "Loop Invoked: " << dec << lp->_invkcount << endl;
    cout << "Routine: " << lp->_routine->_name << endl;
    cout << "Number of calls: " << lp->_routine->_rtnCount << endl;
    cout << "Number of instruction in the routine: "<< lp->_routine->_icount << endl;
    loop_ctr++;
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

  RTN_AddInstrumentFunction(Routine, 0);
  PIN_AddFiniFunction(print_results, NULL);

  /* Never returns */
  PIN_StartProgram();
    
  return 0;
}

