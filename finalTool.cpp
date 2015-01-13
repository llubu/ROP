/*
 * PIN Tool to analyze an application for Landing Pad and 
 * other violations as described in ROP report.
 * Read ROP Report and ROP_README before using this tool.
 *
 */

#include <iostream>
#include <fstream>
#include <list>
#include <sstream>
#include "boost/tuple/tuple.hpp"
#include "pin.H"

#define MAX_THREADS 512
#define OUT_FILE "lp_violation.out"
#define STAT_FILE "stat.out"
#define TRACE_FILE "trace.out"
#define RET_FILE "ret.out"
#define LD_PATH "/lib64/ld-linux-x86-64.so.2"

ofstream OutFile[MAX_THREADS];
ofstream Stat;
ofstream TraceFile;
ofstream RetFile;

static UINT64 icount[MAX_THREADS] = {0};
uint32_t numThreads = 0;
THREADID tIds[MAX_THREADS];
uint32_t gotoCount = 0;
PIN_LOCK lock;
static TLS_KEY tls_key;

typedef list <boost::tuple<ADDRINT, ADDRINT> > tulist;

struct thread_data_t {
    public:
	list<ADDRINT> data_sp;    // Tracks sp value **NOT** ret address
	list<ADDRINT> data_ret;   // Keeps track of return address 
	tulist tuplist;		  // List of Tuples used to track call and Ret address pairs
    public:
	thread_data_t(int i) : data_sp(), data_ret(), tuplist() {}
};

thread_data_t *get_tls(THREADID tid) 
{
    thread_data_t *tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, tid));
    return tdata;
}


VOID PIN_FAST_ANALYSIS_CALL Count(THREADID tid, ADDRINT cnt)
{
    icount[tid] += cnt;
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))

	BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(Count),
		IARG_FAST_ANALYSIS_CALL,
		IARG_THREAD_ID,
		IARG_UINT32, BBL_NumIns(bbl),
		IARG_END);
}

int depth = 10;

/*
 * This function is called each time a ret instruction is seen in the instrumented
 * application. This function takes a PIN Lock at the entry point, make sure you
 * are releasing lock at each function exit point.
 * @arg:
 * tid: Thread ID of the executing thread (PIN specific)
 * sp:  Value of Stack pointer register when ret ins is encountered
 * target: The target of the ret ins i.e. the return address
 * eip: Intruction Pointer of the ret ins
 * push: 1/0 depending on if the immediate previous ins before ret was a memory push
 *
 */

VOID Ret(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip, UINT32 push )
{
    PIN_GetLock(&lock, tid+1);

    unsigned int dep = 0, i = 0;
    IMG imgR, imgT;
    string retName = "ANON", targetName = "ANON", rR = "unknown", tR = "unknown";
    thread_data_t *tdata = get_tls(tid);
    list<ADDRINT>::iterator sp_iter;// = (*tdata).find(sp);
    list<ADDRINT>::iterator ret_iter;// = (*tdata).find(sp);
    tulist::iterator tup_iter;// = (*tdata).find(sp);


    /******************* Uncomment this code to check ONLY for landing pad violations. START HERE ************/

/*
    i = 0;
    for ( tup_iter = tdata->tuplist.begin(); tup_iter != tdata->tuplist.end(); tup_iter++ ) {
	++i;
	if ( target == (tup_iter->get<1>()) ) {
	    RetFile << tid << " Ret Addr Relocated " << hex << target << " " << tup_iter->get<0>() 
		<< " " << std::dec << i << endl;
	    ++gotoCount;			// Keeps track of no of times ret addr was relocated but landing pad are correct
	    tdata->tuplist.erase( tup_iter );	
	    break;
	}
    }
    if ( tup_iter != tdata->tuplist.end() ) { 
	PIN_ReleaseLock(&lock);
	return;
    }
    else {  // Landing Pad Violation  
	// Getting the names of Image and rtn will make this really SLOW. 
	   Comment this before the File IO to make it faster 
	PIN_LockClient();
	imgR = IMG_FindByAddress((ADDRINT)eip);
	imgT = IMG_FindByAddress((ADDRINT)target);
	PIN_UnlockClient();

	if ( IMG_Valid(imgR) ) {
	    retName = IMG_Name(imgR);
	}

	if ( IMG_Valid(imgT) ) {
	    targetName = IMG_Name(imgT);
	}
	rR = RTN_FindNameByAddress((ADDRINT)eip);
	tR = RTN_FindNameByAddress((ADDRINT)target);

	// This checks if the LP violation source or target is in Linker. 
	// These are not Violation as Linker takes and passes control many times without 
	// a call or ret.
	 
	if ( LD_PATH == targetName || LD_PATH == retName )
	    goto overRide;

	OutFile[tid] << tid << hex << "Landing Pad Violation -1  " << sp << " " << target << " " 
	    << eip << " "<<targetName << " " << retName << " " << tR << " " << rR << endl;
overRide:
	PIN_ReleaseLock(&lock);
	return;
    }

*/

    /********* TO CHECK ONLY FOR LANDING PAD VIOLATIONS - END HERE *********************************/
    /**** No need to comment the below code when checking only for LP violation as this function 
      would return before reaching here *****/

    /* Check if stack pointer value i.e. return address location is present */
    for (sp_iter = tdata->data_sp.begin(); sp_iter != tdata->data_sp.end(); sp_iter++) {
	++dep;
	if ( *sp_iter == sp )
	    break;
    }

    --dep;

    if (push) {
	OutFile[tid] << std::dec << tid << "PUSH FOUND" << endl;
	tdata->data_sp.erase(tdata->data_sp.begin());

	PIN_ReleaseLock(&lock);
	return;
    }

    if (sp_iter == tdata->data_sp.end()) {

	/* This is the case where Ret Address is relocated to some other location on stack e.g 
	 Libffi does this to make ffi call portable accross ABIs */

	i = 0;
	for ( tup_iter = tdata->tuplist.begin(); tup_iter != tdata->tuplist.end(); tup_iter++ ) {
	    ++i;
	    if ( target == (tup_iter->get<1>() ) ) {
		RetFile << tid << " Ret Addr Relocated " << hex << target << " " << tup_iter->get<0>() 
		    << ":" << (target - 2) << ":" << (target - tup_iter->get<0>() ) << " "  << std::dec << i << endl;
		++gotoCount;
		tdata->tuplist.erase( tup_iter );
		break;
	    }
	}

	if ( tup_iter != tdata->tuplist.end() ) {
	    PIN_ReleaseLock(&lock);
	    return;
	}

	PIN_LockClient();
	imgR = IMG_FindByAddress((ADDRINT)eip);
	imgT = IMG_FindByAddress((ADDRINT)target);
	PIN_UnlockClient();

	if ( IMG_Valid(imgR) ) {
	    retName = IMG_Name(imgR);
	}

	if ( IMG_Valid(imgT) ) {
	    targetName = IMG_Name(imgT);
	}
	rR = RTN_FindNameByAddress((ADDRINT)eip);
	tR = RTN_FindNameByAddress((ADDRINT)target);

	OutFile[tid] << tid << hex << "Landing Pad Violation -2 " << sp << " " << *(tdata->data_sp.begin())
	    << " " << target << " " << tup_iter->get<0>() << " " << eip << " "<<targetName << " " << retName 
	    << " " << tR << " " << rR << endl;

	PIN_ReleaseLock(&lock);
	return;
    }

    if ( sp_iter != tdata->data_sp.begin() )
	OutFile[tid] << tid << hex <<"ret address not in the beginning!! " << target <<" "<< eip 
	    << " " << sp <<  " " << *(tdata->data_sp.begin()) << " " << dec << dep<< endl;

    depth -= dep;


    tdata->data_sp.erase( tdata->data_sp.begin(), sp_iter);
    tdata->data_sp.erase(sp_iter);

    PIN_ReleaseLock(&lock);
}


/*
 * This function is called each time a call instruction is seen in the instrumented
 * application.
 * @arg:
 * tid: Thread ID of the executing thread (PIN specific)
 * sp:  Value of Stack pointer register when ret ins is encountered
 * target: The target of the ret ins i.e. the return address
 * eip: Intruction Pointer of the ret ins
 * nextIns: Address/PC of the next ins following call ins i.e. the return address pushed on stack
 *
 */

VOID Call(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip, ADDRINT nxtIns )
{
    thread_data_t *tdata = get_tls(tid);

    PIN_GetLock(&lock, tid+1);
    tdata->data_sp.push_front(sp);	// Pushing SP register 
    tdata->data_ret.push_front(nxtIns); // Pushing return address for the call ins
    tdata->tuplist.push_front(boost::tuple<ADDRINT, ADDRINT>(eip, nxtIns));
    depth++;
    PIN_ReleaseLock(&lock);
}

/*
 * This function is called each time a Memory Write instruction is seen in the instrumented
 * application.
 * @arg:
 * tid: Thread ID of the executing thread (PIN specific)
 * ea: Effective address of the memory write.
 * eip: Intruction Pointer of the ret ins
 *
 */

VOID MemWrite(THREADID tid, ADDRINT ea,  ADDRINT eip )
{
    IMG imgR;
    string retName = "ANON", rR = "unknown";

    thread_data_t *tdata = get_tls(tid);
    list<ADDRINT>::const_iterator sp_iter;

    for (sp_iter = tdata->data_sp.begin(); sp_iter != tdata->data_sp.end(); sp_iter++) {
	if ( *sp_iter == ea )
	    break;
    }

    if ( sp_iter != tdata->data_sp.end() ) {

	PIN_LockClient();
	imgR = IMG_FindByAddress((ADDRINT)eip);
	PIN_UnlockClient();

	if ( IMG_Valid(imgR) ) {
	    retName = IMG_Name(imgR);
	}

	rR = RTN_FindNameByAddress((ADDRINT)eip);

	OutFile[tid] << tid << hex << "return address overwrite!!! " << ea << " " 
	    << eip << " " << retName << " " << rR << endl;
    }
}

/*
 * This function is called each time a new Image/library/binary is loaded in intrumented 
 * application address space. Keeps track of load and end address of all images loaded.
 * @arg:
 * img: Image that is just being loaded
 *
 */

VOID ImageLoad(IMG img, VOID *v)
{
    Stat << hex << IMG_Name(img) << " " << IMG_LowAddress(img) << " " << IMG_HighAddress(img) << " " <<endl;
}

/*
 * This function is called each time a new thread is created
 * by the application being intrumented. It creates a thread
 * local storage and does some book keeping.
 * @arg:
 * tid: Thread ID of the thread created by application.
 * 
 */

VOID ThreadStart( THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&lock, tid+1);

    tIds[numThreads] = tid;
    stringstream fn;

    /* If you ever see this then change the logic in code which uses tid to 
       index into open File streams to do File I/O */
    if ( tid != numThreads ) {
	cout << " TID NOT SAME AS NUMTHREADS " << tid << " " << numThreads << endl;
    }

    fn.str("");
    fn << OUT_FILE << "_" << numThreads;
    OutFile[numThreads].open(fn.str().c_str(), ios::out);
    ++numThreads;
    PIN_ReleaseLock(&lock);

    thread_data_t *tdata = new thread_data_t(numThreads-1);
    PIN_SetThreadData(tls_key, tdata, tid);
}


VOID InsTrace(THREADID tid, ADDRINT eip)
{
    TraceFile << tid << " " << hex << eip << endl;
}


VOID Instruction(INS ins, VOID *v)
{
    ADDRINT nextIns;

    if (INS_IsRet(ins)) {

	INS prev = INS_Prev(ins);

	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Ret),
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_STACK_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_UINT32, (INS_Valid(prev) && INS_Opcode(prev) == XED_CATEGORY_PUSH),
		IARG_END);

    }
    else if (INS_IsCall(ins)) {

	nextIns = INS_NextAddress(ins);

	INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(Call),
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_STACK_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_ADDRINT, nextIns,
		IARG_END);
    }
    else if (INS_IsMemoryWrite(ins)) {

	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(MemWrite),
		IARG_THREAD_ID,
		IARG_MEMORYWRITE_EA,
		IARG_INST_PTR,
		IARG_END);
    } 
}

VOID Fini(INT32 code, VOID *v)
{
    uint32_t i;
    /* Just an identifier in Stat trace before ins executed/thread are logged */
    Stat << "DUMP Count DS" << endl;

    for (i = 0; i < MAX_THREADS; i++)
	Stat << icount[i] << endl;

    Stat << "Total Threads started " << numThreads;
    Stat << " Return Address relocatedd COUNT " << gotoCount << endl;
    cout << "Total Threads started " << numThreads;
    cout << " Return Address relocatedd COUNT " << gotoCount << endl;

    for ( i  = 0; i < numThreads; i++) {
	OutFile[i].close();
    } 

    Stat.close();
    TraceFile.close();
    RetFile.close();
}


int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
	return 1;


    Stat.open(STAT_FILE);
    TraceFile.open(TRACE_FILE);
    RetFile.open(RET_FILE);

    PIN_InitLock(&lock);
    tls_key = PIN_CreateThreadDataKey(0);

    //  Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);

    TRACE_AddInstrumentFunction(Trace, 0);

    IMG_AddInstrumentFunction(ImageLoad, 0);

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
