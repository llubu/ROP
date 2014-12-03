#include <iostream>
#include <map>
#include <sstream>
#include <stdio.h>
#include <assert.h>
#include "pin.H"

#define ASPLOS_PATH "/var/services/homes/adabral/elider/pintools/asplos/"
#define RANGE_PATH ASPLOS_PATH "/ranges"

FILE *rangetrace;
int count;
uint32_t pltcount = 0;

VOID TraceImageLoad(IMG img, VOID *v)
{
	cerr << "Load: " << IMG_Name(img) << endl;
	bool plt = false;
	uint64_t addr1 = 0;
	uint64_t addr2 = 0;
	stringstream ss;
	
	++pltcount;
	ss << RANGE_PATH << count++ << ".out";
	rangetrace = fopen(ss.str().c_str(), "w");
	for (SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		//cerr << "    " << SEC_Name(sec) << endl;
		if (SEC_Name(sec) == ".plt") {
			//cerr << IMG_Name(img) << " " << SEC_Name(sec) << " : " << SEC_Address(sec) << " ";
			addr1 = SEC_Address(sec);
			plt = true;
		} else if (plt){
			//cerr << SEC_Address(sec) << endl;
			plt = false;
			addr2 = SEC_Address(sec);
			//rangetrace = fopen(RANGE_PATH(count), "w");
			assert(rangetrace && "rangetrace file handler is correctly opened.");
			printf("%lx:%lx\n", addr1, addr2);
			fwrite(&addr1, 8, 1, rangetrace);
			fwrite(&addr2, 8, 1, rangetrace);  // to get read friendly trace file
			//fclose(rangetrace);
			//ranges.add(addr1, addr2);
		}
	}
	fclose(rangetrace);
}

VOID TraceImageUnload(IMG img, VOID *v)
{
	cerr << "Unload: " << IMG_Name(img) << endl;

}


VOID Fini(INT32 code, VOID *v)
{
    cout << "PLT COUNT "<< pltcount << endl;
}

INT32 Usage()
{
    PIN_ERROR("Some usage\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
/******************************************************************************/


int main(int argc, char * argv[])
{
    PIN_InitSymbols();	// Initialize symbol table code used for RTN by PIN 
     
		/*
		rangetrace = fopen(RANGE_PATH, "w");
		fclose(rangetrace);
		*/

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

		IMG_AddInstrumentFunction(TraceImageLoad, 0);
		IMG_AddUnloadFunction(TraceImageUnload, 0);
    
    PIN_AddFiniFunction(Fini, 0);
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
