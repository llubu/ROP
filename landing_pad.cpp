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
//ofstream OutFile;
ofstream Stat;
ofstream TraceFile;
ofstream RetFile;

//ofstream CallFile;
static UINT64 icount[MAX_THREADS] = {0};
uint32_t numThreads = 0;
THREADID tIds[MAX_THREADS];
uint32_t gotoCount = 0;
PIN_LOCK lock;
static TLS_KEY tls_key;

typedef list <boost::tuple<ADDRINT, ADDRINT> > tulist;

struct thread_data_t {
    public:
	list<ADDRINT> data_sp; // Tracks sp value **NOT** ret address
	list<ADDRINT> data_ret; // Keeps track of return address 
	tulist tuplist;
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

VOID Ret(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip, UINT32 push )
{
    PIN_GetLock(&lock, tid+1);
    unsigned int dep = 0, i = 0;
    IMG imgR, imgT;
    string retName = "ANON", targetName = "ANON", rR = "unknown", tR = "unknown";
    thread_data_t *tdata = get_tls(tid);
/*
    list<ADDRINT> *tdata = data_ar[tid];
    list<ADDRINT> *retId = ret_ad[tid];
    */
    list<ADDRINT>::iterator sp_iter;// = (*tdata).find(sp);
    list<ADDRINT>::iterator ret_iter;// = (*tdata).find(sp);
    tulist::iterator tup_iter;// = (*tdata).find(sp);
    

    for (sp_iter = tdata->data_sp.begin(); sp_iter != tdata->data_sp.end(); sp_iter++) {
	++dep;
	if ( *sp_iter == sp )
	    break;
    }

    --dep;

   /* This is the case where Ret Address is relocated to some other location on stack */
       i = 0;
       for ( tup_iter = tdata->tuplist.begin(); tup_iter != tdata->tuplist.end(); tup_iter++ ) {
	   ++i;
	   if ( target == (tup_iter->get<1>()) 
		   && ( (tup_iter->get<0>() == (target - 0x5)) 
		       || ( tup_iter->get<0>() == (target - 0x2)) ) ) {
	       RetFile << tid << " Ret Addr Relocated " << hex << target << " " << tup_iter->get<0>() << ":" << (target - 2) << ":" << (target - tup_iter->get<0>() ) << " "  << std::dec << i << endl;
	       ++gotoCount;
	       tdata->tuplist.erase( tup_iter );
	       break;
	   }
       }
//cout << " CHECK1" << endl;
       if ( tup_iter != tdata->tuplist.end() ) {
	   PIN_ReleaseLock(&lock);
	   return;
       }
       else {
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

	   if ( LD_PATH == targetName || LD_PATH == retName )
	       goto overRide;

	   OutFile[tid] << tid << hex << "LP not found!! " << sp << " " << target << " " << eip << " "<<targetName << " " << retName << " " << tR << " " << rR << endl;
overRide:
	   PIN_ReleaseLock(&lock);
	   return;
       }






    if (push) {
	OutFile[tid] << std::dec << tid << "PUSH FOUND" << endl;
	tdata->data_sp.erase(tdata->data_sp.begin());

	
    PIN_ReleaseLock(&lock);
	return;
    }

   if (sp_iter == tdata->data_sp.end()) {

       /* This is the case where Ret Address is relocated to some other location on stack */
       i = 0;
       for ( tup_iter = tdata->tuplist.begin(); tup_iter != tdata->tuplist.end(); tup_iter++ ) {
	   ++i;
	   if ( target == (tup_iter->get<1>()) && ( (tup_iter->get<0>() == (target - 0x5)) || ( tup_iter->get<0>() == (target - 0x2)) ) ) {
	       RetFile << tid << " Ret Addr Relocated " << hex << target << " " << tup_iter->get<0>() << ":" << (target - 2) << ":" << (target - tup_iter->get<0>() ) << " "  << std::dec << i << endl;
	       ++gotoCount;
	       tdata->tuplist.erase( tup_iter );
	       break;
	   }
       }
//cout << " CHECK1" << endl;
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

	//cout << hex << tup_iter->get<0>() << ":" << tup_iter->get<1>() << endl;
	OutFile[tid] << tid << hex << "ret address not found!! " << sp << " " << *(tdata->data_sp.begin())
	    << " " << target << " " << tup_iter->get<0>() << " " << eip << " "<<targetName << " " << retName << " " << tR << " " << rR << endl;

    PIN_ReleaseLock(&lock);
	return;
    }

    if ( sp_iter != tdata->data_sp.begin() )
	OutFile[tid] << tid << hex <<"ret address not in the beginning!! " << target <<" "<< eip << " " << sp <<  " " << *(tdata->data_sp.begin()) << " " << dec << dep<< endl;

      depth -= dep;


    tdata->data_sp.erase( tdata->data_sp.begin(), sp_iter);
    tdata->data_sp.erase(sp_iter);

    PIN_ReleaseLock(&lock);
}

VOID Call(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip, ADDRINT nxtIns )
{
    thread_data_t *tdata = get_tls(tid);

    PIN_GetLock(&lock, tid+1);
    tdata->data_sp.push_front(sp);	// Pushing SP register 
    tdata->data_ret.push_front(nxtIns); // Pushing return address for the call ins
    tdata->tuplist.push_front(boost::tuple<ADDRINT, ADDRINT>(eip, nxtIns));
    depth++;
    PIN_ReleaseLock(&lock);
    if ( eip == 12 )
//    cout << hex << (nxtIns - eip ) << " : " << nxtIns <<  " : " << eip << endl;
    cout << hex << tdata->tuplist.begin()->get<0>() << " " <<tdata->tuplist.begin()->get<1>() << endl;
}

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

	OutFile[tid] << tid << hex << "return address overwrite!!! " << ea << " " << eip << " " << retName << " " << rR << endl;
    }
}

VOID ImageLoad(IMG img, VOID *v)
{
    Stat << hex << IMG_Name(img) << " " << IMG_LowAddress(img) << " " << IMG_HighAddress(img) << " " <<endl;// IMG_NumRegions(img) << endl;
}


VOID ThreadStart( THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&lock, tid+1);

    tIds[numThreads] = tid;
    stringstream fn;

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
    Stat << "DUMP Count DS" << endl;

   for (i = 0; i < MAX_THREADS; i++)
	Stat << icount[i] << endl;

    Stat << "Total Threads started " << numThreads;
    cout << " GOTO COUNT " << gotoCount << endl;

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
