#include <iostream>
#include <fstream>
//#include <stdio.h>
#include <string>
#include <assert.h>
#include <string.h>
#include <map>
#include <list>
#include <set>
#include <unistd.h>
#include "pin.H"

#define ROUTE_PATH "/var/services/homes/adabral/elider/pintools/asplos/"

#define RANGE_PATH ROUTE_PATH "/finalrange.out"
#define TRACE_PATH ROUTE_PATH "/apache.out"
#define BIN_PATH   ROUTE_PATH "/traceBIN.out"
#define DIS_PATH   ROUTE_PATH "/dis.out"
#define PAGE_PATH  ROUTE_PATH "/page.out"
#define FRQ_PATH   ROUTE_PATH "/freq.out"
#define FORK_LOG   ROUTE_PATH "/fork.out"

#define MAX_INSTRUCTIONS 100000000000
#define MAX_ADDR 0x10000000000
#define DUMPFRQ 1000 // Unique ins executed count is dumped after x call2plt are found

PIN_LOCK lock;
INT32 numThreads = 0;
THREADID ids[50000];
std::map<uint64_t, uint64_t> global_t_map;	// TO store unique copies of source, target pairs
std::map<uint64_t, uint64_t> global_plt_map;	// TO store unique copies of source, target pairs

pid_t parent_pid;
uint64_t fcount = 0;

size_t pageSize = 0x0;
uint64_t uInsCount = 0;
uint64_t patchCount = 0;

ifstream rangestream;
ofstream stream;
ofstream binstream;
ofstream disstream;
ofstream pagestream;
ofstream frqstream;
ofstream forkstream;
/*
   FILE *rangetrace;
   FILE *trace;
   FILE *bintrace;
   FILE *distrace;
 */

VOID Fini(INT32 code, VOID *v);

// =====================================================================================

std::map<uint64_t, uint64_t>:: iterator t_iter; // Map iterator
class plt_range{
    list<uint64_t> addresses;
    set<uint64_t> filter;

    public:
    plt_range() : addresses(), filter() { }

    void add(uint64_t start, uint64_t end) {
	if (filter.find(start) != filter.end())
	    return;
	addresses.push_back(start);
	addresses.push_back(end);
	addresses.sort();

	filter.insert(start);
    }

    bool in_plt(uint64_t addr) {
	int counter = 0;
	uint64_t address;
	for (list<uint64_t>::iterator it = addresses.begin(); it != addresses.end(); it++) {
	    address = *it;
	    if (addr < address) {
		if (counter%2 == 1) {
		    return true;
		} else {
		    break;
		}
	    }
	    counter++;
	}
	return false;
    }

    void print() {
	disstream << "Ranges start" << endl;
	for (list<uint64_t>::iterator it = addresses.begin(); it != addresses.end(); it++) {
	    //printf("%lx\n", *it);
	   // cout << std::hex << *it << std::dec << endl;
	    disstream << std::hex << *it << std::dec << endl;
	}
	disstream << "Ranges end" << endl;
    }
} ranges;

struct thread_data_t
{
    public:
	std::map<uint64_t, uint64_t> t_map;	// TO store unique copies of source, target pairs
	std::map<uint64_t, uint64_t> plt_map;	// TO store unique copies of source, target pairs
	std::map<uint64_t, uint64_t> count_map;	// TO store count of each library call in its thread

	int id;
	uint64_t inscount;
	uint64_t prev_ins;
	uint64_t curr_ins;

	uint64_t lib_call_addr;
    public:
	thread_data_t(int i) : t_map(), plt_map(), count_map(), id(i), inscount(0), prev_ins(0), curr_ins(0), lib_call_addr(0) { }
};

static TLS_KEY tls_key;

thread_data_t* get_tls(THREADID threadid)
{
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
    return tdata;
}

VOID inscounter_prev_curr(void *ip, THREADID threadid)
{
    thread_data_t* tdata = get_tls(threadid);
    tdata->inscount++;
    if (tdata->inscount % (MAX_INSTRUCTIONS/16) == 0) {
	//printf("%d %ld\n", tdata->id, tdata->inscount);
//	std::cout << tdata->id << " " << tdata->inscount << endl;
	disstream << tdata->id << " " << tdata->inscount << endl;
    }

    tdata->prev_ins = tdata->curr_ins;
    tdata->curr_ins = (uint64_t)ip;

    PIN_GetLock(&lock, threadid+1);
    ++uInsCount;

    if ( uInsCount % DUMPFRQ == 0 ) { /* Dumps No of Unique patches found on DUMPFRQ instructions executed so far */
	frqstream << uInsCount << ":" <<  patchCount << endl;
    }

    PIN_ReleaseLock(&lock);

    if (tdata->inscount > MAX_INSTRUCTIONS) {
	disstream << "MAX INS REACHED" << endl;
	PIN_Detach();
    }
}

VOID lib_call(void *ip, ADDRINT target, THREADID threadid)
{
    thread_data_t* tdata = get_tls(threadid);
    assert((uint64_t)ip == tdata->curr_ins);
//    string rtn_name = RTN_FindNameByAddress(target);
    //if (rtn_name.find("plt") != string::npos && (uint64_t)ip < MAX_ADDR) {
    if ((uint64_t)ip < MAX_ADDR) {
	tdata->lib_call_addr = tdata->curr_ins;
	//printf("found call %d\n", tdata->id);
    } else {
	//printf("do you see mee? %s %p\n",rtn_name.c_str(),ip);
    }
}

VOID indirect_jmp(void *ip, ADDRINT target, THREADID threadid)
{
    thread_data_t* tdata = get_tls(threadid);
    assert((uint64_t)ip == tdata->curr_ins);
//    string rtn_name = RTN_FindNameByAddress(target);
    //if (tdata->lib_call_addr != 0 && tdata->lib_call_addr == tdata->prev_ins && rtn_name.find("plt") == string::npos && target < MAX_ADDR) {
    if (tdata->lib_call_addr != 0 && tdata->lib_call_addr == tdata->prev_ins && target < MAX_ADDR) {
	if (ranges.in_plt((uint64_t)ip)) {

	    t_iter = tdata->t_map.find(tdata->prev_ins);  /* Look if this ins already exist in t_map  */
	    if ( t_iter == tdata->t_map.end() ) {  /* Unique Call to PLT sec  */
	    	++patchCount;
	    }

	    tdata->t_map[tdata->prev_ins] = target;// - (prev_ins+5);
	    tdata->plt_map[tdata->prev_ins] = (uint64_t)ip;// - (prev_ins+5);
	    if (tdata->count_map.count(tdata->prev_ins) == 0)
		tdata->count_map[tdata->prev_ins] = 0;
	    tdata->count_map[tdata->prev_ins] += 1;

    //printf(".");
//	    std::cout << ".";
	    disstream << ".";
	} else {
	    disstream << endl << std::hex << (uint64_t)ip << std::dec << endl;
	}
    }
}

VOID Instruction(INS ins, VOID *v)
{
    //char *dis;
    //dis = (char *)malloc(50);
    //string s = INS_Disassemble(ins);
    //strncpy(dis, s.c_str(), 50);
    //dis[49] = '\0';
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)inscounter_prev_curr, IARG_INST_PTR, IARG_THREAD_ID, IARG_END);

    if (INS_IsDirectBranchOrCall(ins)) {
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)lib_call, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_THREAD_ID, IARG_END);
    } else if (INS_IsIndirectBranchOrCall(ins) && !INS_IsRet(ins) && !INS_IsCall(ins)) {
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)indirect_jmp, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_THREAD_ID, IARG_END);
    }

}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&lock, threadid+1);
    ids[numThreads] = threadid;
    numThreads++;
    PIN_ReleaseLock(&lock);

    thread_data_t* tdata = new thread_data_t(numThreads-1);
    PIN_SetThreadData(tls_key, tdata, threadid);
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 flags, VOID *v)
{
    thread_data_t* tdata = get_tls(threadid);
    std::map<uint64_t, uint64_t>:: iterator iter; // Map iterator
    PIN_GetLock(&lock, threadid+1);
    for (iter = tdata->t_map.begin(); iter != tdata->t_map.end(); iter++)
    {
	global_t_map[iter->first] = iter->second;
	global_plt_map[iter->first] = tdata->plt_map[iter->first];
    }
    PIN_ReleaseLock(&lock);
    delete tdata;
}

/******************************************************************************/

VOID DFini(VOID *v)
{
    Fini(0, 0);
}

VOID Fini(INT32 code, VOID *v)
{

    /*
       cerr << "start" << endl;
       for ( IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
       for (SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
       cerr << SEC_Name(sec) << endl;
       }
       }
       cerr << "end" << endl;
     */


    PIN_GetLock(&lock, 1);
    uint64_t t1 = 0 , t2 = 0;
    for (int i=0; i< numThreads; i++) {
	thread_data_t* tdata = get_tls(ids[i]);
	//fprintf(trace, "\n%ld:<==\n", tdata->inscount);
	stream << tdata->inscount << ":<==" << endl;
	for (t_iter = tdata->t_map.begin(); t_iter != tdata->t_map.end(); t_iter++)
	{
	    t1 = t_iter->first;
	    t2 = t_iter->second;
	    if (!ranges.in_plt(tdata->plt_map[t1]) || ranges.in_plt(t2)) {
		cerr << "filter" << endl;
		continue;
	    } else {
		cerr << "not filter" << endl;
	    }

	    //printf(":0x%lx:0x%lx\n", t_iter->first, t_iter->second) ;
//	    std::cout << std::hex << t_iter->first << std::dec << ":" << std::hex << t_iter->second << std::dec << endl;
	    //fprintf(trace, "%ld:0x%lx:0x%lx:0x%lx\n", tdata->count_map[t1], t_iter->first, tdata->plt_map[t1], t_iter->second) ;
	    stream << tdata->count_map[t1] << ":" << std::hex << t1 << std::dec
		<< ":" << std::hex << tdata->plt_map[t1] << std::dec
		<< ":" << std::hex << t2 << std::dec << endl;
	    //fwrite(&t1, 8, 1, bintrace);
	    //fwrite(&t2, 8, 1, bintrace);  // to get read friendly trace file
	    pagestream <<  hex << (t1 & ~(pageSize-1)) << endl;   // Dumping the Page Base address where patch calls/jmp are identified
	    binstream.write((char *)&t1, 8);
	    binstream.write((char *)&t2, 8);
	}
    }
    cerr << endl;

    stream.close();
    binstream.close();
    disstream.close();
    pagestream.close();
    frqstream.close();
    forkstream.close();
    //fclose(trace);
    //fclose(bintrace);
    //fclose(distrace);
    //printf("\n IN FINI  \n");
 //   std::cout << endl << " IN FINI " << endl;
    PIN_ReleaseLock(&lock);
}

VOID TraceImageLoad(IMG img, VOID *v)
{
    cerr << "Load: " << IMG_Name(img) << endl;
    bool plt = false;
    uint64_t addr1 = 0;
    uint64_t addr2 = 0;
    for (SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
	cerr << "    " << SEC_Name(sec) << endl;
	if (SEC_Name(sec) == ".plt") {
	    //cerr << IMG_Name(img) << " " << SEC_Name(sec) << " : " << SEC_Address(sec) << " ";
	    addr1 = SEC_Address(sec);
	    plt = true;
	} else if (plt){
	    //cerr << SEC_Address(sec) << endl;
	    plt = false;
	    addr2 = SEC_Address(sec);
	    ranges.add(addr1, addr2);
	}
    }
}

VOID TraceImageUnload(IMG img, VOID *v)
{
    cerr << "Unload: " << IMG_Name(img) << endl;
}


VOID AfterForkChild( THREADID threadid, const CONTEXT* ctxt, VOID *arg)
{
    fcount++;
    
    if ((PIN_GetPid() == parent_pid) || (getppid() != parent_pid))
    {
	cerr << "PIN_GetPid() fails in child process" << " TID: " << threadid <<  endl;
//	exit(-1);
    }
    forkstream << "CHILD PID " << PIN_GetPid() << " TID: " << threadid << endl;
}

VOID BeforeFork( THREADID threadid, const CONTEXT* ctxt, VOID *arg)
{
    parent_pid = PIN_GetPid();
    forkstream << "BEFORE FORK IN PARENT  PID " << parent_pid << " TID: " << threadid << endl;
}



VOID OOM_Handler(size_t size, VOID *v)
{
    //printf("Out of Memory!!!! %lx\n", size);
    std::cout << "Out of Memory!!!! " << std::hex << size << std::dec << endl;
    //fclose(bintrace);
}

INT32 Usage()
{
    PIN_ERROR("Traces the call/jmp to plt section. **** target stored is absolute, make it relative while patching in linker****\n" 
	    + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
/******************************************************************************/


int main(int argc, char * argv[])
{
    cout << "Pintool attached" << endl;
    PIN_InitSymbols();	// Initialize symbol table code used for RTN by PIN 

    stream.open(TRACE_PATH, ios::out);
    binstream.open(BIN_PATH, ios::out | ios::binary);
    disstream.open(DIS_PATH, ios::out);
    pagestream.open(PAGE_PATH, ios::out);
    frqstream.open(FRQ_PATH, ios::out);
    rangestream.open(RANGE_PATH, ios::in | ios::binary);
    forkstream.open(FORK_LOG);

    uint64_t addr1, addr2;
    while (!rangestream.eof()) {
	rangestream.read((char *)&addr1, 8);
	rangestream.read((char *)&addr2, 8);
	ranges.add(addr1, addr2);
    }
    rangestream.close();
//    pageSize = mapped_region::get_page_size();
//    cout << "PAGE SIZE IS " << hex << pageSize << std::endl;

    pageSize = sysconf(_SC_PAGE_SIZE);

    stream << hex << "PAGE SIZE-hex :" <<  pageSize << endl;
    /*
       trace = fopen(TRACE_PATH, "w");
       bintrace = fopen(BIN_PATH, "wb");
       distrace = fopen(DIS_PATH, "w");

       rangetrace = fopen(RANGE_PATH, "r");
       if (rangetrace) {
       cout << "Range file opened" << endl;
       } else {
       cout << "Range file not opened" << endl;
       }
       uint64_t addr1, addr2;
       int size;
       while (!feof(rangetrace)) {
       size = fread(&addr1, 8, 1, rangetrace);
       if (size < 8)
       break;
       size = fread(&addr2, 8, 1, rangetrace);
       if (size < 8)
       break;
       ranges.add(addr1, addr2);
       }
       fclose(rangetrace);
     */
    cout << "Range file closed" << endl;

    ranges.print();

    /*
       for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ) {
       disstream << IMG_Name(img) << endl;
       }
     */

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Initialize the lock
    PIN_InitLock(&lock);

    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);

    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);

    PIN_AddForkFunction(FPOINT_BEFORE, BeforeFork, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkChild, 0);
 
    // TODO when thread closes... clear some memory
    //PIN_AddThreadFiniFunction(ThreadFini, 0);

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    PIN_AddDetachFunction(DFini, 0);

    PIN_AddOutOfMemoryFunction(OOM_Handler, 0);

    //IMG_AddInstrumentFunction(TraceImageLoad, 0);
    //IMG_AddUnloadFunction(TraceImageUnload, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
