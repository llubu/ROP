#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <stdio.h>
#include <assert.h>
#include "pin.H"

#define ROOT_PATH "/var/services/homes/adabral/elider/pintools/asplos/"

#define RANGE_PATH ROOT_PATH "/pltrange.out"
#define PLT_LOG ROOT_PATH "/pltlog.out"
#define FORK_LOG ROOT_PATH "/forklog.out"

//FILE *rangetrace;
int count;
uint64_t fcount = 0;


//ofstream pltstream;
ofstream rangedump;
pid_t parent_pid;
//ofstream forkstream;

uint32_t pltcount = 0;

VOID TraceImageLoad(IMG img, VOID *v)
{
//    PIN_LockClient();
    bool plt = false;
    uint64_t addr1 = 0;
    uint64_t addr2 = 0;
//    int ret;

//    stringstream ss;
//    ss << "ranges" << count++ << ".out";
//    rangetrace = fopen(ss.str().c_str(), "w");
    for (SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
	//cerr << "    " << SEC_Name(sec) << endl;
	if (SEC_Name(sec) == ".plt") {
//	    cout << " IF" << IMG_Name(img) << " " << SEC_Name(sec) << " : " << SEC_Address(sec) << " ";
	    addr1 = SEC_Address(sec);
	    plt = true;
	} else if (plt){

    	    rangedump.open(RANGE_PATH, ios::out | ios::binary | ios::app );
    	    cerr << "Load: " << IMG_Name(img) << endl;
//	    cout << "ELSE " << SEC_Address(sec) << endl;
	    plt = false;
	    addr2 = SEC_Address(sec);
	    //rangetrace = fopen(RANGE_PATH(count), "w");
//	    assert(rangetrace && "rangetrace file handler is correctly opened.");
	    assert(rangedump && "rangetrace file handler is correctly opened.");
//	    printf("%lx:%lx\n", addr1, addr2);
	    cout << hex << addr1 << " " << addr2 << endl;
	    pltcount++;

//	    fwrite(&addr1, 8, 1, rangetrace) ) !=  8 ) 
//	    fwrite(&addr2, 8, 1, rangetrace);  // to get read friendly trace file
	    rangedump.write((char *)&addr1, sizeof(uint64_t));
	    rangedump.write((char *)&addr2, sizeof(uint64_t));

	    rangedump.close();
//	    pltstream << hex << addr1 << ":" << addr2 << IMG_Name(img) << SEC_Name(sec) << endl; 
	    //fclose(rangetrace);
	    //ranges.add(addr1, addr2);
	}
    }
//    PIN_UnlockClient();
//    fclose(rangetrace);
}

VOID AfterForkChild( THREADID threadid, const CONTEXT* ctxt, VOID *arg)
{
    fcount++;
    
    if ((PIN_GetPid() == parent_pid) || (getppid() != parent_pid))
    {
	cerr << "PIN_GetPid() fails in child process" << " TID: " << threadid <<  endl;
//	exit(-1);
    }
//    forkstream << "CHILD PID " << PIN_GetPid() << " TID: " << threadid << endl;
}

VOID BeforeFork( THREADID threadid, const CONTEXT* ctxt, VOID *arg)
{
    parent_pid = PIN_GetPid();
//    forkstream << "BEFORE FORK IN PARENT  PID " << parent_pid << " TID: " << threadid << endl;
}

VOID TraceImageUnload(IMG img, VOID *v)
{
    cerr << "Unload: " << IMG_Name(img) << endl;
//    pltstream << "Unload: " << IMG_Name(img) << endl;
}

INT32 Usage()
{
    PIN_ERROR("Some usage\n" 
	    + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}



VOID Fini(INT32 code, VOID *v)
{
//    fclose(rangetrace);
//    pltstream.close();
    rangedump.close();
//    forkstream << "Fork Count" << fcount << endl;
//    forkstream.close();
    cout << "PLT COUNT " << pltcount << endl;
}

/******************************************************************************/


int main(int argc, char * argv[])
{
    PIN_InitSymbols();	// Initialize symbol table code used for RTN by PIN 

    /*
       rangetrace = fopen(RANGE_PATH, "w");
       fclose(rangetrace);
     */

//    rangetrace = fopen(RANGE_PATH, "w");
    rangedump.open(RANGE_PATH, ios::out | ios::binary );
    rangedump.close();
//    pltstream.open(PLT_LOG, ios::out);
//    forkstream.open(FORK_LOG);
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    
//    PIN_AddForkFunction(FPOINT_BEFORE, BeforeFork, 0);
//    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkChild, 0);
    IMG_AddInstrumentFunction(TraceImageLoad, 0);
    IMG_AddUnloadFunction(TraceImageUnload, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
