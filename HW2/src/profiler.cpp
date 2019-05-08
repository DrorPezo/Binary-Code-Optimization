#include <stdio.h>
#include <map>
#include <string>
#include "pin.H"

std::map<ADDRINT, std::map<ADDRINT, unsigned long> > cflows;
unsigned long cflow_count   = 0;

typedef struct _loopCount{
  ADDRINT target_address;
  int count_seen;
  int count_invoked;
  int mean_taken;
  int diff_count;
  string routine_name;
  ADDRINT routine_address;
  int routine_ins_count;
} loopCount;

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
static void instrument_insn(INS ins, void *v)
{
  if(!INS_IsBranchOrCall(ins)) return;

  IMG img = IMG_FindByAddress(INS_Address(ins));
  if(!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return;

  INS_InsertPredicatedCall(
    ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)count_cflow, 
    IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
    IARG_END
  );

  if(INS_HasFallThrough(ins)) {
    INS_InsertPredicatedCall(
      ins, IPOINT_AFTER, (AFUNPTR)count_cflow, 
      IARG_INST_PTR, IARG_FALLTHROUGH_ADDR, 
      IARG_END
    );
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
  printf("******* CONTROL TRANSFERS *******\n");
  for(i = cflows.begin(); i != cflows.end(); i++) {
    target = i->first;
    for(j = i->second.begin(); j != i->second.end(); j++) {
      ip = j->first;
      count = j->second;
      printf("0x%08jx <- 0x%08jx: %3lu (%0.2f%%)\n", 
             target, ip, count, (double)count/cflow_count*100.0);
    } 
  }

}

static void print_usage(){
  std::string help = KNOB_BASE::StringKnobSummary();

  fprintf(stderr, "\nProfile call and jump targets\n");
  fprintf(stderr, "%s\n", help.c_str());
}

/*****************************************************************************
 *                               Main function                               *
 *****************************************************************************/

int main(int argc, char *argv[])
{
  PIN_InitSymbols();
  if(PIN_Init(argc,argv)) {
    print_usage();
    return 1;
  }

  INS_AddInstrumentFunction(instrument_insn, NULL);
  PIN_AddFiniFunction(print_results, NULL);

  /* Never returns */
  PIN_StartProgram();
    
  return 0;
}

