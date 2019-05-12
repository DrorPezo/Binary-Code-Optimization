#include <stdio.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <map>
#include <vector>
#include <iostream>
#include <string>
#include "pin.H"

int fall_through_ctr = 0;
std::map<ADDRINT, std::map<ADDRINT, unsigned long>> countSeen; 
std::map<ADDRINT,unsigned long> loopInvoked; 
std::map<ADDRINT,unsigned long> diffs; 
ofstream outFile;
vector<string> procs_data;

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
  UINT64 _invkcount;
  UINT64 _diffs;
  double _meanTaken;
  ADDRINT _head;
  ADDRINT _tail;
  struct RtnCount *_routine;
  struct LoopProp *_next;
} LOOP_PROP;

typedef struct Proc{
    int n;
    char *full_line;
} proc;

RTN_COUNT * RtnList = 0;
LOOP_PROP * LoopList = 0;

/* ===================================================================== */
/* Sort aux function                                               */
/* ===================================================================== */

bool sort_aux(Proc *p1, Proc *p2){
    return ((p1->n) > (p2->n));
}

/* ===================================================================== */
/* Sorting out csv file                                                  */
/* ===================================================================== */

void sort_out(){
    vector<Proc*> procs;
    for (std::vector<string>::iterator it = procs_data.begin() ; it != procs_data.end(); ++it){
        const char *s = strrchr((*it).c_str(), ',');
        char *num = strdup(s);
        int number = atoi(num+1);
        Proc *new_proc = (Proc*)malloc(sizeof(Proc));
        new_proc->n = number;
        new_proc->full_line = strdup((*it).c_str());
        procs.push_back(new_proc);
    }
    sort(procs.begin(), procs.end(), sort_aux);
    for (std::vector<Proc *>::iterator it = procs.begin() ; it != procs.end(); ++it){
        outFile << (*it)->full_line;
    }
}

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
    fall_through_ctr = 0;
  }
  else{
    loopInvoked[target]++;
    fall_through_ctr++;
    if(fall_through_ctr > 1){
      diffs[target]++;
    }
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
    lc->_diffs = diffs[target];
 
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

  ostringstream stream;
  for (LOOP_PROP * lp = LoopList; lp; lp = lp->_next){
    double mean_taken = (lp->_invkcount == 0) ? (double)lp->_itcount : (double)lp->_itcount/(double)lp->_invkcount;
    stream << showbase << hex << lp->_head << ","
    << showbase << hex << lp->_tail << ","
    << dec << lp->_itcount << ","
    << dec << lp->_invkcount << ","
    << mean_taken << ","
    << lp->_diffs << ","
    << lp->_routine->_name << ","
    << lp->_routine->_rtnCount << ","
    << lp->_routine->_icount << endl;
    string str =  stream.str();
    procs_data.push_back(str);
  }
  sort_out();
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

