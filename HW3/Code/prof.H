#include <stdio.h>
#include <fstream>
#include <sstream>
#include <numeric> 
#include <functional>
#include <iomanip>
#include <iterator>
#include <algorithm>
#include <map>
#include <vector>
#include <iostream>
#include <string>
#include "pin.H"

ofstream outFile;
std::map<ADDRINT, std::map<ADDRINT, unsigned long>> countSeen; 
std::map<ADDRINT,unsigned long> loopInvoked; 
std::map<ADDRINT,vector<unsigned long>> iters_per_inv;
vector<string> loops_data;
unsigned long iter_cnt = 0;

// data structure to handle routine properties 
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

// data structure to handle loop properties 
typedef struct LoopProp
{
  UINT64 _itcount; //total iteration count (countSeen)
  UINT64 _invkcount; 
  UINT64 diffs; 
  vector<unsigned long> _iters_cnt; //iters per invokation
  double _meanTaken; 
  ADDRINT _head;
  ADDRINT _tail;
  struct RtnCount *_routine;
  struct LoopProp *_next;
} LOOP_PROP;

// aux data structure for the csv sorting
typedef struct Loopc{
  int n;
  char *full_line;
} Loopc;

// routines list
RTN_COUNT * RtnList = 0;
// loops list
LOOP_PROP * LoopList = 0;

/* ===================================================================== */
/* Sort aux function                                               */
/* ===================================================================== */
bool sort_aux(Loopc *p1, Loopc *p2){
    return ((p1->n) > (p2->n));
}

/* ===================================================================== */
/* Sorting out csv file                                                  */
/* ===================================================================== */
void sort_out(){
    vector<Loopc*> loopcs;
    for (std::vector<string>::iterator it = loops_data.begin() ; it != loops_data.end(); ++it){
      const char *s = strchr((*it).c_str(), ','); // for sorting from the back - use strrchr instead of strchr
      char *num = strdup(s);
      int number = atoi(num+1);
      Loopc *new_loopc = (Loopc*)malloc(sizeof(Loopc));
      new_loopc->n = number;
      new_loopc->full_line = strdup((*it).c_str());
      loopcs.push_back(new_loopc);
    }
    sort(loopcs.begin(), loopcs.end(), sort_aux);
    for (std::vector<Loopc *>::iterator it = loopcs.begin() ; it != loopcs.end(); ++it){
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
      iter_cnt++;
    }
  }
  else{
    loopInvoked[target]++;
    iters_per_inv[target].push_back(iter_cnt);
    iter_cnt = 0;
  }
}

VOID docount(UINT64 * counter)
{
  (*counter)++;
}

/*****************************************************************************
 *                            Aux function for instrumentation               *
 *****************************************************************************/
RTN_COUNT * new_rtn(RTN rtn)
{
    RTN_COUNT * rc = new RTN_COUNT;
    rc->_name = RTN_Name(rtn);
    rc->_address = RTN_Address(rtn);
    rc->_icount = RTN_NumIns(rtn);
    rc->_rtnCount = 0;
    rc->_rtn = rtn;
    rc->_next = RtnList;
    RtnList = rc;
    rc->_tail = INS_Address(RTN_InsTail(rtn));
    return rc;
}

/*****************************************************************************
 *                         Instrumentation function                        *
 *****************************************************************************/
VOID Routine(RTN rtn, VOID *v)
{            
    RTN_Open(rtn);
    RTN_COUNT *rc = new_rtn(rtn);
    // Insert a call at the entry point of a routine to increment the call count
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);
  
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
    RTN_Close(rtn);
}

/*****************************************************************************
 *                               Other functions                             *
 *****************************************************************************/

//calculate differences between two adjacent loops iterations number
UINT64 calculate_diff(std::vector<unsigned long> itrs){
  UINT64 diff_cnt = 0;
  vector<unsigned long> diffs (itrs.size());
  std::adjacent_difference(itrs.begin(), itrs.end(), diffs.begin());
  for (std::vector<unsigned long>::iterator it = diffs.begin() ; it != diffs.end(); ++it){
    if ((*it) != 0){
      diff_cnt++;
    }
  }
  return diff_cnt;
}

// process loops data for printing it out
void process_loop_data(){
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
    lc->_iters_cnt = iters_per_inv[target];
    lc->diffs = calculate_diff(lc->_iters_cnt);
 
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
}

// printing results to csv file
static void print_results(INT32 code, void *v)
{
  process_loop_data();
  ostringstream stream;
  string str;
  for (LOOP_PROP * lp = LoopList; lp; lp = lp->_next){
    double mean_taken = (lp->_invkcount == 0) ? lp->_invkcount : (double)lp->_itcount/(double)lp->_invkcount;
    stream
    << showbase << hex << lp->_head << ","
    << dec << lp->_itcount << ","
    << dec << lp->_invkcount << ","
    << mean_taken << ","
    << lp->diffs << "," 
    << lp->_routine->_name << ","
    << showbase << hex << lp->_routine->_address << ","
    << dec << (lp->_routine)->_rtnCount << endl;
    str =  stream.str();
    loops_data.push_back(str);
    stream.str("");
  }
  sort_out();
}

// usage function
static void print_usage()
{
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
}

