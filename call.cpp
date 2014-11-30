#include <iostream>
#include <fstream>
#include <list>

#include "pin.H"

#define CALL_FILE "call.out"
#define MAP_FILE "ffmap.out"
#define TARLIB "/var/services/homes/adabral/ROP/mozilla-build/mozilla-release/obj-x86_64-unknown-linux-gnu/dist/bin/libxul.so"

ofstream CallFile;
ofstream Mapstream;

PIN_LOCK lock;
uint64_t start = 0x7fffddf14000, end = 0x7fffe1e0f000;

VOID Call( THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip)
{
    
//    IMG imgRc, imgTc;
//    string ipNamec = "ANON", targetNamec = "ANON", iRc = "unknown", tRc = "unknown";

//    PIN_LockClient();
//    imgRc = IMG_FindByAddress((ADDRINT)eip);
//    imgTc = IMG_FindByAddress((ADDRINT)target);
//    PIN_UnlockClient();

    /*
    if ( IMG_Valid(imgRc) && IMG_Valid(imgTc) ) {
	ipNamec = IMG_Name(imgRc);
	targetNamec = IMG_Name(imgTc);
    }
    else {
	cout << " INVALID IMAGES";
	return;
    }

    iRc = RTN_FindNameByAddress((ADDRINT)eip);
    tRc = RTN_FindNameByAddress((ADDRINT)target);

    if ( !(targetNamec.compare(TARLIB)) ) {
          CallFile << hex << "BRANCH" << " "<< eip << " " << ipNamec << " " << iRc << " " << 
	    target << " " << tRc << endl;
*/
//    if ( ( eip < start || eip > end) &&  target >= start && target <= end) 
        
    PIN_GetLock(&lock, tid+1);
	CallFile << hex << "B " << tid  << " "<< eip << " " << target << " " << sp  << endl;
    PIN_ReleaseLock(&lock);
    
}

VOID ImageLoad(IMG img, VOID *v)
{
    if ( IMG_Name(img) == TARLIB ) {
//	cout << IMG_Name(img) << " " << hex << IMG_LowAddress(img) << " " << IMG_HighAddress(img) << " "
//	    << IMG_NumRegions(img) << endl;
	start = IMG_LowAddress(img);
	end = IMG_HighAddress(img);
    }
    Mapstream << hex << IMG_Name(img) << " " << IMG_LowAddress(img) << " " << IMG_HighAddress(img) << " " << IMG_NumRegions(img) << endl;
}

VOID ImageUnload(IMG img, VOID *v)
{
    Mapstream << hex << " UL" << IMG_Name(img) << endl;
}

VOID Instruction(INS ins, VOID *v)
{
//    if ( INS_IsBranch(ins) && !( INS_IsCall(ins)) && !(INS_IsRet(ins)) ) {
    if ( INS_IsBranch(ins) )  {

	    INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(Call),
  	        IARG_THREAD_ID,
		IARG_REG_VALUE, REG_ESP,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_END);
    }
}


VOID Fini(INT32 code, VOID *v)
{
    CallFile.close();
    Mapstream.close();

}


int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
	return 1;

    CallFile.open(CALL_FILE);
    Mapstream.open(MAP_FILE);

    IMG_AddInstrumentFunction(ImageLoad, 0);
    IMG_AddUnloadFunction(ImageUnload, 0);
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
