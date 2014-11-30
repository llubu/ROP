#include <iostream>
#include <fstream>
#include <list>
#include <sstream>

#include "pin.H"

#define MAX_THREADS 512
#define OUT_FILE "ropth.out"
#define STAT_FILE "stat.out"
//#define CALL_FILE "call.out"
#define TARLIB "/var/services/homes/adabral/ROP/mozilla-build/mozilla-release/obj-x86_64-unknown-linux-gnu/dist/bin/libxul.so"

ofstream OutFile;
ofstream Stat;
//ofstream CallFile;
ADDRINT start = 0x0 , end = 0x0;

PIN_LOCK lock;
static UINT64 icount[MAX_THREADS] = {0};
THREADID ids[50000];
//list<ADDRINT> RetAddrLocs;
UINT64 my_tid = 0;
INT32 numThreads = 0;
list<ADDRINT> *data_ar[MAX_THREADS];

std::list<ADDRINT>::iterator sp_iter;
struct thread_data_t {
    public:
	std::list<ADDRINT> th_list;   // To get the rsp per thread
	int depth;

    public:
	thread_data_t(int i) : th_list(), depth(10) {}
};

static TLS_KEY tls_key;

thread_data_t* get_tls(THREADID threadid) 
{
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
    return tdata;
}

VOID PIN_FAST_ANALYSIS_CALL Count(THREADID tid, ADDRINT cnt)
{
    if ( my_tid < tid )
	my_tid = tid;
//   return;
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

VOID Ret(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip, UINT32 push)
{
    unsigned int dep = 0;
    IMG imgR, imgT;
    string retName = "ANON", targetName = "ANON", rR = "unknown", tR = "unknown";

    thread_data_t* tdata = get_tls(tid);

    for (sp_iter = tdata->th_list.begin(); sp_iter != tdata->th_list.end(); sp_iter++) {
	++dep;
	if ( *sp_iter == sp )
	    break;
    }

    if (push) {
	OutFile << "PUSH FOUND" << endl;
	tdata->th_list.erase(tdata->th_list.begin());
    	//cout << "RET FROM RET-1" << tid<<endl;
	return;
    }
    if (sp_iter == tdata->th_list.end()) {
	//		cerr << hex << "ret address not found!! " << sp << " " << *(RetAddrLocs.begin())
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


	OutFile << tid << hex << "ret address not found!! " << sp << " " << *(tdata->th_list.begin())
	    << " " << target << " " << eip << " "<<targetName << " " << retName << " " << tR << " " << rR << endl;

    	//cout << "RET FROM RET-2" << tid <<endl;
	return;
    }

    if (sp_iter != tdata->th_list.begin())
	OutFile << tid << hex <<"ret address not in the beginning!! " << target <<" "<< eip << " " << sp <<endl;

//    depth -= distance((*tdata).begin(), sp_iter) + 1;
      tdata->depth -= dep;

//    OutFile << "Distance " << distance(RetAddrLocs.begin(), sp_iter)  << endl;
//    for (int i=0; i < depth; i++) cerr << " ";
//    cerr << hex << tid << " ret " << sp <<  " " << target << endl;
//    if ( sp_iter == RetAddrLocs.begin() ) {
//	RetAddrLocs.erase(sp_iter);
//	return;
//    }

    tdata->th_list.erase(tdata->th_list.begin(), sp_iter);
    tdata->th_list.erase(sp_iter);
    //cout << "RET FROM RET-3" << tid<<endl;
}

VOID Call(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip)
{
//    //cout << "CALL " << tid << hex << " " << sp << " " << target << " " << eip << endl;
//    return;
//    for (int i=0; i < depth; i++) cerr << " ";
//    cerr << hex << tid << " call " << sp << " " << target << endl;
    
    thread_data_t* tdata = get_tls(tid);
    tdata->th_list.push_front(sp);
    tdata->depth++;
}

VOID MemWrite(THREADID tid, ADDRINT ea)
{
    thread_data_t* tdata = get_tls(tid);

    for (sp_iter = tdata->th_list.begin(); sp_iter != tdata->th_list.end(); sp_iter++) {
	if ( *sp_iter == ea )
	    break;
    }

    if ( sp_iter != tdata->th_list.end() )
	OutFile << "return address overwrite!!!" << endl;
    //cout << "RET FROM MEWRITE" << tid<<endl;
}

VOID Branch( THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip ) {
//    if ( target >= start && target <= end) {
//	OutFile << "BRANCH" << hex <<" "<< eip << " " <<  target << " " << sp << endl;
//    }
}

VOID ImageLoad(IMG img, VOID *v)
{
    if ( IMG_Name(img) == TARLIB ) {
//	cout << IMG_Name(img) << " " << hex << IMG_LowAddress(img) << " " << IMG_HighAddress(img) << " "
//	    << IMG_NumRegions(img) << endl;
	start = IMG_LowAddress(img);
	end = IMG_HighAddress(img);
    }
    Stat << hex << IMG_Name(img) << " " << IMG_LowAddress(img) << " " << IMG_HighAddress(img) << " " <<endl;// IMG_NumRegions(img) << endl;
}

VOID Instruction(INS ins, VOID *v)
{
    /*
    if ( INS_IsBranch(ins) && !(INS_IsCall(ins)) && !(INS_IsRet(ins)) ) {

	INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(Branch), 
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_STACK_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_END);
    }

    else */if (INS_IsRet(ins)) {

	INS prev = INS_Prev(ins);
	//cout<< "CALL TO RET" << endl;

	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Ret),
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_STACK_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_UINT32, (INS_Valid(prev) && INS_Opcode(prev) == XED_CATEGORY_PUSH),
		IARG_END);

    }
    else if (INS_IsCall(ins)) {
	//cout << "CALL TO CALL" << endl;

	INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(Call),
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_STACK_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_END);
    }
    else if (INS_IsMemoryWrite(ins)) {
	//cout<< "CALL TO MEWRITE" << endl;

	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(MemWrite),
		IARG_THREAD_ID,
		IARG_MEMORYWRITE_EA,
		IARG_END);
    }
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&lock, threadid+1);
    cout << "TID: " << threadid << endl;
    ids[numThreads] = threadid;
    numThreads++;
    PIN_ReleaseLock(&lock);

    thread_data_t* tdata = new thread_data_t(numThreads-1);
    tdata->depth = 10;
    PIN_SetThreadData(tls_key, tdata, threadid);
}

VOID Fini(INT32 code, VOID *v)
{
    Stat << "DUMP Count DS" << endl;

   for (UINT32 i = 0; i < MAX_THREADS; i++)
	Stat << icount[i] << endl;
    Stat << "TID = " << my_tid;

      OutFile.close();
      Stat.close();
//    CallFile.close();

//    cerr << "SIZE" << RetAddrLocs.size() << endl;

    //	for (auto ea : RetAddrLocs)
    //	list<ADDRINT>::const_iterator ret_iter;
    //	for ( ret_iter = RetAddrLocs.begin(); ret_iter != RetAddrLocs.end(); ret_iter++ ) 
    //		cerr << hex << *ret_iter<< endl;
}


int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
	return 1;

      OutFile.open(OUT_FILE);
      Stat.open(STAT_FILE);
//    CallFile.open(CALL_FILE);

    // Initialize the lock
    PIN_InitLock(&lock);

    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);

    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);

    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);


    TRACE_AddInstrumentFunction(Trace, 0);

    IMG_AddInstrumentFunction(ImageLoad, 0);

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
