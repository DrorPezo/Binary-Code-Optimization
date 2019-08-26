#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <numeric>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>
#define MAX_FINE_NAME_SIZE  30
int UNROLL_LVL = 0;


/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
ifstream inputFile;
ofstream outFile;
std::map<ADDRINT, std::map<ADDRINT, unsigned long> > countSeen; 
std::map<ADDRINT,unsigned long> loopInvoked; 
std::map<ADDRINT,vector<unsigned long>> iters_per_inv;
vector<string> loops_data;
char profileFilename[MAX_FINE_NAME_SIZE];
int fd;
unsigned long iter_cnt = 0;

/* ================================================================== */
// Types and structures 
/* ================================================================== */
typedef struct instr_table_struct {
	UINT64 count;
	ADDRINT offset;
} instr_table_t;

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

typedef struct hot_loop_data{
    ADDRINT target_addr;
    UINT64 cnt;
    char name[MAX_FINE_NAME_SIZE];
} hot_loop_data_t;

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,    "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "no_tc_commit", "0", "Do not commit translated code");

// routines list
RTN_COUNT * RtnList = 0;
// loops list
LOOP_PROP * LoopList = 0;
std::ofstream* out = 0;
vector<hot_loop_data_t*> hot_loops;

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;	
int tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct { 
	ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;
	bool hasNewTargAddr;
	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_category_enum_t category_enum;
	unsigned int size;
	int new_targ_entry;
} instr_map_t;


instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;


// total number of routines in the main executable module:
int max_rtn_count = 0;

// Tables of all candidate routines to be translated:
typedef struct { 
	ADDRINT rtn_addr; 
	USIZE rtn_size;
	int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
	bool isSafeForReplacedProbe;	
} translated_rtn_t;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;
string desired_rtn = "mainSimpleSort";


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


      IMG img = IMG_FindByAddress(RTN_Address(rtn));
      if(!IMG_Valid(img)) return;
      if (!IMG_IsMainExecutable(img))
		  return;


    RTN_Open(rtn);
    RTN_COUNT *rc = new_rtn(rtn);
    // Insert a call at the entry point of a routine to increment the call count
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);
  
    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
      if(!INS_IsDirectBranch(ins)) continue; //&& !INS_HasFallThrough(ins)) continue; 
      //IMG img = IMG_FindByAddress(INS_Address(ins));
      //if(!IMG_Valid(img)) return;

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


/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<int>   KnobInst(KNOB_MODE_WRITEONCE,    "pintool",
    "opt", "0", "opt run");

KNOB<BOOL>   KnobProf(KNOB_MODE_WRITEONCE,    "pintool",
    "prof", "0", "prof run");


/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img)
{
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			// Open the RTN.
            RTN_Open( rtn );

			cerr << RTN_Name(rtn) << ":" << endl;

			for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {				
	              cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			}

			// Close the RTN.
            RTN_Close( rtn );
		}
	}
}


/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
	// debug print decoded instr:
	char disasm_buf[2048];

    xed_uint64_t runtime_address = reinterpret_cast<xed_uint64_t>(address);  // set the runtime adddress for disassembly 	

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);	

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cerr << "invalid opcode" << endl;
	  return;
  }
 
  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;  
 
}


/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{	
	for (int i=0; i < num_of_instr_map_entries; i++) {
		for (int j=0; j < translated_rtn_num; j++) {
			if (translated_rtn[j].instr_map_entry == i) {

				RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

				if (rtn == RTN_Invalid()) {
					cerr << "Unknwon"  << ":" << endl;
				} else {
				  cerr << RTN_Name(rtn) << ":" << endl;
				}
			}
		}
		dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);		
	}
}


/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
{
	cerr << dec << instr_map_entry << ": ";
	cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
	cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
	cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

	ADDRINT new_targ_addr;
	if (instr_map[instr_map_entry].new_targ_entry >= 0)
		new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
	else
		new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

	cerr << " new_targ_addr: " << hex << new_targ_addr;
	cerr << "    new instr:";
	dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}


/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

	  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
	  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

	  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	  if (!xed_ok){
		  cerr << "invalid opcode" << endl;
		  return;
	  }
 
	  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

	  cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

	  size = xed_decoded_inst_get_length (&new_xedd);	
  }
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */


/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size)
{

	// copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

	if (xed_decoded_inst_get_length (xedd) != size) {
		cerr << "Invalid instruction decoding" << endl;
		return -1;
	}

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
	
	xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
	  orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;	
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
	
	xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;
	}	
	
	// add a new entry in the instr_map:
	
	instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
	instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
	instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr; 
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
	instr_map[num_of_instr_map_entries].new_targ_entry = -1;
	instr_map[num_of_instr_map_entries].size = new_size;	
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

	num_of_instr_map_entries++;

	// update expected size of tc:
	tc_cursor += new_size;    	     

	if (num_of_instr_map_entries >= max_ins_count) {
		cerr << "out of memory for map_instr" << endl;
		return -1;
	}
	

    // debug print new encoded instr:
	if (KnobVerbose) {
		cerr << "    new instr:";
		dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
	}

	return new_size;
}


/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
int chain_all_direct_br_and_call_target_entries()
{
	for (int i=0; i < num_of_instr_map_entries; i++) {			    

		if (instr_map[i].orig_targ_addr == 0)
			continue;

		if (instr_map[i].hasNewTargAddr)
			continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {

            if (j == i)
			   continue;
	
            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {
                instr_map[i].hasNewTargAddr = true; 
	            instr_map[i].new_targ_entry = j;
                break;
			}
		}
	}
   
	return 0;
}


/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry) 
{
	//debug print:
	//dump_instr_map_entry(instr_map_entry);

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

	if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
		return 0;

	//cerr << "Memory Operands" << endl;
	bool isRipBase = false;
	xed_reg_enum_t base_reg = XED_REG_INVALID;
	xed_int64_t disp = 0;
	for(unsigned int i=0; i < memops ; i++)   {

		base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
		disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

		if (base_reg == XED_REG_RIP) {
			isRipBase = true;
			break;
		}
		
	}

	if (!isRipBase)
		return 0;

			
	//xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
	xed_int64_t new_disp = 0;
	xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

	unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

	// modify rip displacement. use direct addressing mode:	
	new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
	xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

	//Set the memory displacement using a bit length 
	xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;
			
	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);
	
	xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry); 
		return -1;
	}				

	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}


/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}
	
	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {
		if (RTN_Invalid() != RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr))
			cerr << "ERROR: Invalid direct jump from translated code to original code in routine: " << 
		      RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
		else
		    cerr << "ERROR: Invalid direct jump from translated code to original code. " << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}

	// check for cases of direct jumps/calls back to the orginal target address:
	if (instr_map[instr_map_entry].new_targ_entry >= 0) {
		cerr << "ERROR: Invalid jump or call instruction" << endl;
		return -1;
	}

	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
				

	xed_encoder_instruction_t  enc_instr;

	ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
		               instr_map[instr_map_entry].new_ins_addr - 
					   xed_decoded_inst_get_length (&xedd);

	if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

	if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


	xed_encoder_request_t enc_req;

	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}
   

	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
	    dump_instr_map_entry(instr_map_entry); 
        return -1;
    }

	// handle the case where the original instr size is different from new encoded instr:
	if (olen != xed_decoded_inst_get_length (&xedd)) {
		
		new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
	               instr_map[instr_map_entry].new_ins_addr - olen;

		if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

		if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (!convert_ok) {
			cerr << "conversion to encode request failed" << endl;
			return -1;
		}

		xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
			dump_instr_map_entry(instr_map_entry);
			return -1;
		}		
	}

	
	// debug prints:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry); 
	}
		
	instr_map[instr_map_entry].hasNewTargAddr = true;
	return olen;	
}


/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry) 
{					

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	xed_int32_t  new_disp = 0;	
	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;


	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: unrecognized branch displacement" << endl;
		return -1;
	}

	// fix branches/calls to original targ addresses:
	if (instr_map[instr_map_entry].new_targ_entry < 0) {
	   int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
	   return rc;
	}

	ADDRINT new_targ_addr;		
	new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
		
	new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

	xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

	// the max displacement size of loop instructions is 1 byte:
	xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
	if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
	  new_disp_byts = 1;
	}

	// the max displacement size of jecxz instructions is ???:
	xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
	if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
	  new_disp_byts = 1;
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

	xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
	unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    
	xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
		char buf[2048];		
		xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
	    cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
  		return -1;
	}		

	new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;

	new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);
	
	xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}				

	//debug print of new instruction in tc:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}				


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;	

	do {
		
		size_diff = 0;

		if (KnobVerbose) {
			cerr << "starting a pass of fixing instructions displacements: " << endl;
		}

		for (int i=0; i < num_of_instr_map_entries; i++) {

			instr_map[i].new_ins_addr += size_diff;
				   
			int rc = 0;

			// fix rip displacement:			
			rc = fix_rip_displacement(i);
			if (rc < 0)
				return -1;

			if (rc > 0) { // this was a rip-based instruction which was fixed.

				if (instr_map[i].size != (unsigned int)rc) {
				   size_diff += (rc - instr_map[i].size); 					
				   instr_map[i].size = (unsigned int)rc;								
				}

				continue;   
			}

			// check if it is a direct branch or a direct call instr:
			if (instr_map[i].orig_targ_addr == 0) {
				continue;  // not a direct branch or a direct call instr.
			}


			// fix instr displacement:			
			rc = fix_direct_br_call_displacement(i);
			if (rc < 0)
				return -1;

			if (instr_map[i].size != (unsigned int)rc) {
			   size_diff += (rc - instr_map[i].size);
			   instr_map[i].size = (unsigned int)rc;
			}

		}  // end int i=0; i ..

	} while (size_diff != 0);

   return 0;
 }

/*****************************************/
/* rtn_is_hot() */
/*****************************************/
bool rtn_is_hot(RTN rtn){
	const string rtn_name = RTN_Name(rtn);
	for (std::vector<hot_loop_data_t*>::iterator it = hot_loops.begin() ; it != hot_loops.end(); ++it){
		// cout << (*it)->name << endl;
		// cout << showbase << dec << (*it)->cnt << " " << showbase << hex << (*it)->addr << " " << endl;  
		
		if (strcmp((*it)->name, const_cast<char*> (rtn_name.c_str())) == 0){
				return true;
		}
	}
	return false;
}

/*****************************************/
/* unroll(RTN rtn, ADDRINT start_addr, ADDRINT end_addr) */
/*****************************************/
// Made generic for further project use
void unroll(RTN rtn, ADDRINT start_addr, ADDRINT end_addr){
		int rc;
		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
				if(INS_Address(ins) < start_addr){
						//debug print of orig instruction:
						if (KnobVerbose) {
							cerr << "old instr: ";
							cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
							//xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));				   			
						}				

						ADDRINT addr = INS_Address(ins);
									
						xed_decoded_inst_t xedd;
						xed_error_enum_t xed_code;							
						
						xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

						xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
						if (xed_code != XED_ERROR_NONE) {
							cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
							translated_rtn[translated_rtn_num].instr_map_entry = -1;
							break;
						}

						// Add instr into instr map:
						rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
						if (rc < 0) {
							cerr << "ERROR: failed during instructon translation." << endl;
							translated_rtn[translated_rtn_num].instr_map_entry = -1;
							break;
						}
						// char buf[2048];	
						// xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, INS_Address(ins), 0, 0);
						// cerr << "0x" << hex << INS_Address(ins) << " " << buf << endl;
				}
				else{
						break;
				}
		}
		for(int i = 0; i < UNROLL_LVL; i++){
				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
						// cerr << INS_Address(ins) << endl;
						if(INS_Address(ins) < start_addr){
								continue;
						}
						if(INS_Address(ins) < end_addr){
								//debug print of orig instruction:
								if (KnobVerbose) {
									cerr << "old instr: ";
									cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;		   			
								}				

								ADDRINT addr = INS_Address(ins);
											
								xed_decoded_inst_t xedd;
								xed_error_enum_t xed_code;							
								
								xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

								xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
								if (xed_code != XED_ERROR_NONE) {
									cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
									translated_rtn[translated_rtn_num].instr_map_entry = -1;
									break;
								}

								// Add instr into instr map:
								rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
								if (rc < 0) {
									cerr << "ERROR: failed during instructon translation." << endl;
									translated_rtn[translated_rtn_num].instr_map_entry = -1;
									break;
								}
						}
						else{
								// if(INS_Address(ins) == 0x40af0c){
								// 	char buf[2048];	
								// 	// xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, INS_Address(ins), 0, 0);
								// 	cerr << "0x" << hex << INS_Address(ins) << " " << buf << endl;
								// }
								break;
						}
				}
				// changing last loop's instruction 
				// xed_encoder_instruction_t enc_instr;				
				// xed_inst1(&enc_instr, dstate, 
				// 					XED_ICLASS_JNL, 32,
				// 					xed_relbr((xed_uint32_t)end_addr, 32)
				// 					);

				// xed_encoder_request_t enc_req;
				// xed_encoder_request_zero_set_mode(&enc_req, &dstate);
				// if(!xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
				// 		cout << "failed encoder request" << endl;
				// } 

				// xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES] = {0};
				// // unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
				// // unsigned int new_size = 0;
				// // xed_error_enum_t xed_error = xed_encode(&enc_req, enc_buf, max_size, &new_size);

				// // if (xed_error != XED_ERROR_NONE) {
				// // 	cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
				// // 	continue;
				// // }	
				// cerr << "print" << endl;
				// xed_decoded_inst_t new_xedd;
				// xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

				// xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(enc_buf), XED_MAX_INSTRUCTION_BYTES);
				// if (xed_code != XED_ERROR_NONE) {
				// 		cerr << "ERROR: xed decode failed" << endl;
				// 		continue;
				// }
				// rc = add_new_instr_entry(&new_xedd, 0, xed_decoded_inst_get_length (&new_xedd));
				// if (rc < 0) {
				// 	cerr << "ERROR: failed during instruction translation." << endl;
				// 	translated_rtn[translated_rtn_num].instr_map_entry = -1;
				// 	break;
				// }	

				// char buff[2048];	
				// xed_format_context(XED_SYNTAX_INTEL, &new_xedd, buff, 2048, end_addr, 0, 0);
				// cerr << "0x" << hex << end_addr << " " << buff << endl;
		}
		xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES] = {0};
		// unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
		// unsigned int new_size = 0;
		// xed_error_enum_t xed_error = xed_encode(&enc_req, enc_buf, max_size, &new_size);

		// if (xed_error != XED_ERROR_NONE) {
		// 	cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
		// 	continue;
		// }	
		cerr << "print" << endl;
		xed_decoded_inst_t new_xedd;
		xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

		xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(enc_buf), XED_MAX_INSTRUCTION_BYTES);
		if (xed_code != XED_ERROR_NONE) {
				cerr << "ERROR: xed decode failed" << endl;
		}
		rc = add_new_instr_entry(&new_xedd, 0, xed_decoded_inst_get_length (&new_xedd));
		if (rc < 0) {
				cerr << "ERROR: failed during instruction translation." << endl;
				translated_rtn[translated_rtn_num].instr_map_entry = -1;
		}	

		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
			if(INS_Address(ins) <= end_addr){
					continue;
			}
			//debug print of orig instruction:
			if (KnobVerbose) {
					cerr << "old instr: ";
					cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;		   			
			}				

			ADDRINT addr = INS_Address(ins);
						
			xed_decoded_inst_t xedd;
			xed_error_enum_t xed_code;							
			
			xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

			xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
			if (xed_code != XED_ERROR_NONE) {
				cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
				translated_rtn[translated_rtn_num].instr_map_entry = -1;
				break;
			}

			// Add instr into instr map:
			rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
			if (rc < 0) {
				cerr << "ERROR: failed during instructon translation." << endl;
				translated_rtn[translated_rtn_num].instr_map_entry = -1;
				break;
			}
			// char buf[2048];	
			// xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, INS_Address(ins), 0, 0);
			// cerr << "0x" << hex << INS_Address(ins) << " " << buf << endl;
		}
}

/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/
int find_candidate_rtns_for_translation(IMG img)
{
    int rc;
		ADDRINT starting_addr = 0x409fde;
		ADDRINT ending_addr = 0x40a076;
	// go over routines and check if they are candidates for translation and mark them for translation:

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {	
			// comapring with the functions from the profile file by address and not by name
			// due to function override
			if (rtn == RTN_Invalid()) {
			  cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
  			  continue;
			}

			if(rtn_is_hot(rtn)){
				translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);			
				translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
				translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
				translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;	

				// Open the RTN.
				RTN_Open(rtn);         
				if(RTN_Name(rtn) == desired_rtn){
						unroll(rtn, starting_addr, ending_addr);
				}
				else{
						for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
								//debug print of orig instruction:
								if (KnobVerbose) {
									cerr << "old instr: ";
									cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
									//xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));				   			
								}				

								ADDRINT addr = INS_Address(ins);
											
								xed_decoded_inst_t xedd;
								xed_error_enum_t xed_code;							
								
								xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

								xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
								if (xed_code != XED_ERROR_NONE) {
									cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
									translated_rtn[translated_rtn_num].instr_map_entry = -1;
									break;
								}

								// Add instr into instr map:
								rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
								if (rc < 0) {
									cerr << "ERROR: failed during instructon translation." << endl;
									translated_rtn[translated_rtn_num].instr_map_entry = -1;
									break;
								}
						} // end for INS...

						// debug print of routine name:
						if (KnobVerbose) {
							cerr <<   "rtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num << endl;
						}			
				}
				// Close the RTN.
				RTN_Close( rtn );
				translated_rtn_num++;
			}
		} // end for RTN..
	} // end for SEC...


	return 0;
}

/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
	int cursor = 0;

	for (int i=0; i < num_of_instr_map_entries; i++) {

	  if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
		  cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
	      return -1;
	  }	  

	  memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

	  cursor += instr_map[i].size;
	}

	return 0;
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines() 
{
	// Commit the translated functions: 
	// Go over the candidate functions and replace the original ones by their new successfully translated ones:

	for (int i=0; i < translated_rtn_num; i++) {

		//replace function by new function in tc
	
		if (translated_rtn[i].instr_map_entry >= 0) {
				    
			if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {						

				RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

				//debug print:				
				if (rtn == RTN_Invalid()) {
					cerr << "committing rtN: Unknown";
				} else {
					cerr << "committing rtN: " << RTN_Name(rtn);
				}
				cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

						
				if (RTN_IsSafeForProbedReplacement(rtn)) {

					AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);							
					
					if (origFptr == NULL) {
						cerr << "RTN_ReplaceProbed failed.";
					} else {
						cerr << "RTN_ReplaceProbed succeeded. ";
					}
					cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
							<< " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;	

					dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);												
				}												
			}
		}
	}
}


/****************************/
/* allocate_and_init_memory */
/****************************/ 
int allocate_and_init_memory(IMG img) 
{
	// Calculate size of executable sections and allocate required memory:
	//
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;


		if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
			lowest_sec_addr = SEC_Address(sec);

		if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
			highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

		// need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			if (rtn == RTN_Invalid())
				continue;
			
			max_ins_count += RTN_NumIns  (rtn);
			max_rtn_count++;
		}
	}

	max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.
	
	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}


	// Allocate memory for the array of candidate routines containing inlineable function calls:
	// Need to estimate size of inlined routines.. ???
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}


	// get a page size in the system:
	int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32MB afar:		
	//		
	char * tc_addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) tc_addr == 0xffffffffffffffff) {
		cerr << "failed to allocate tc" << endl;
        return -1;
	}
    //ADDRINT highest_limit = (ADDRINT) (lowest_sec_addr + MAXINT);
    //ADDRINT init_hi_addr = (ADDRINT) (highest_sec_addr + 0x100000) & 0xfffffffffff00000;
    //char * tc_addr = NULL;
    //for (ADDRINT addr = init_hi_addr; addr < highest_limit; addr += 0x100000) {
    //    tc_addr = (char *) mmap((void *)addr, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    //    if ((ADDRINT) tc_addr != 0xffffffffffffffff)
    //            break;
    //}
	//if ((ADDRINT) tc_addr == 0xffffffffffffffff) {
	//   cerr << "failed to allocate a translation cache" << endl;
    //   return -1;
	//}		
	
	tc = (char *)tc_addr;
	return 0;
}



/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v)
{
	// debug print of all images' instructions
	//dump_all_image_instrs(img);


    // Step 0: Check the image and the CPU:
	if (!IMG_IsMainExecutable(img))
		return;

	int rc = 0;

	// step 1: Check size of executable sections and allocate required memory:	
	rc = allocate_and_init_memory(img);
	if (rc < 0)
		return;

	cout << "after memory allocation" << endl;

	
	// Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
	rc = find_candidate_rtns_for_translation(img);
	if (rc < 0)
		return;

	cout << "after identifying candidate routines" << endl;	 
	
	// Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
	rc = chain_all_direct_br_and_call_target_entries();
	if (rc < 0 )
		return;
	
	cout << "after calculate direct br targets" << endl;

	// Step 4: fix rip-based, direct branch and direct call displacements:
	rc = fix_instructions_displacements();
	if (rc < 0 )
		return;
	
	cout << "after fix instructions displacements" << endl;


	// Step 5: write translated routines to new tc:
	rc = copy_instrs_to_tc();
	if (rc < 0 )
		return;

	cout << "after write all new instructions to memory tc" << endl;

   if (KnobDumpTranslatedCode) {
	   cerr << "Translation Cache dump:" << endl;
       dump_tc();  // dump the entire tc

	   cerr << endl << "instructions map dump:" << endl;
	   dump_entire_instr_map();     // dump all translated instructions in map_instr
   }

	// Step 6: Commit the translated routines:
	//Go over the candidate functions and replace the original ones by their new successfully translated ones:
	if (!KnobDoNotCommitTranslatedCode) {
		commit_translated_routines();	
		cout << "after commit translated routines" << endl;
	}
}

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

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool translated routines of an Intel(R) 64 binary"
         << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
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
				UNROLL_LVL = KnobInst.Value();
        string line;
        char *s;
        inputFile.open("loop-count.csv");

        while (getline (inputFile,line))
        {
            char* l = const_cast<char*> (line.c_str());             
            s = strtok(l, ",");  
            hot_loop_data_t *loop_data = (hot_loop_data_t*)malloc(sizeof(hot_loop_data_t));
            int cnt = 0;
            int cnt_seen;
            char* rtn_name;
            ADDRINT loop_address;
            while (s){
								if (cnt == 0){
										loop_address = (long)strtol(s, NULL, 0);
										loop_data->target_addr = loop_address;
									  // cout  << showbase << hex << loop_address << ' ';
								}

                if(cnt == 1){
                    cnt_seen = atoi(s);
                    loop_data->cnt = cnt_seen;
										// cout << dec << showbase << loop_data->cnt << ' ';
                }

                if(cnt == 5){
                    rtn_name = s;
                    strcpy(loop_data->name, rtn_name);
										// cout << loop_data->name << ' ';
                }

                s = strtok(NULL, ",");
                cnt++;        
						}
						// cout << endl;

						hot_loops.push_back(loop_data);
						// cout << dec << showbase << hot_loops.size() << endl;

						if(hot_loops.size() == 10){
								break;
					  }
        }

        // Register ImageLoad
	    	IMG_AddInstrumentFunction(ImageLoad, 0);
        // Start the program, never returns
        PIN_StartProgramProbed();
    }

    /* Never returns */
    PIN_StartProgram();

    return 0;
}

