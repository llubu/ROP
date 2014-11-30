#include <iostream>
#include <fstream>
#include <list>
#include <sstream>

#include "pin.H"

#define MAX_THREADS 512
#define OUT_FILE "cnt.out"
#define STAT_FILE "stat.out"
//#define CALL_FILE "call.out"
#define TARLIB "/var/services/homes/adabral/ROP/mozilla-build/mozilla-release/obj-x86_64-unknown-linux-gnu/dist/bin/libxul.so"
#define FFI_CALL 0x24a5f40
#define FFI_CALL_UNIX64 0x24a74c8
#define FF64IP 0x24a75a3
#define FFITAR 0x24a60c0
#define FF64END 0x24a7631
#define FFEND 0x24a673c
#define FF64PLT 0x981c80
#define FF64CALL 0x24a7511
#define ANONST 0x7fffbc358000
#define ANONEND 0x7fffbc500000

//ofstream OutFile[MAX_THREADS];
ofstream OutFile;
ofstream Stat;
//ofstream CallFile;
ADDRINT start = 0x0 , end = 0x0;

static UINT64 icount[MAX_THREADS] = {0};
//list<ADDRINT> RetAddrLocs;
UINT64 my_tid = 0;
list<ADDRINT> *data_ar[MAX_THREADS];
bool leaflag = false;

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
int depth = 10;

VOID Ret(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip, UINT32 push)
{
 //   cout << "RET " << tid << hex << " " << sp << " " << target << " " << eip << " " << push << endl;
//    return;
    unsigned int dep = 0;
    IMG imgR, imgT;
    string retName = "ANON", targetName = "ANON", rR = "unknown", tR = "unknown";

    list<ADDRINT> *tdata = data_ar[tid];
    list<ADDRINT>::iterator sp_iter;// = (*tdata).find(sp);
    list<ADDRINT>::iterator dep_iter;// = (*tdata).find(sp);

    for (sp_iter = (*tdata).begin(); sp_iter != (*tdata).end(); sp_iter++) {
	++dep;
	if ( *sp_iter == sp )
	    break;
    }

    --dep;

    if (push) {
	OutFile << "PUSH FOUND" << endl;
	(*tdata).erase((*tdata).begin());
    	//cout << "RET FROM RET-1" << tid<<endl;
	return;
    }


    if ( target >= (start+FFI_CALL_UNIX64) && target <= (start+FF64END) ) {
	OutFile << tid << " RET-2-FF64 " << hex << eip << " " << target << " " << sp  << endl;
    }
 
    if ( eip >= (start+FFI_CALL_UNIX64) && eip <= (start+FF64END) ) {
	OutFile << tid << " RET-FRM-FF64 " << hex << eip << " " << target << " " << sp  << endl;
    }
/*
   if ( eip >= (ANONST) && eip <= (ANONEND) ) {
	OutFile << tid << " RET-I " << hex << eip << " " << target << " " << sp << endl;
   }
   if ( target >= (ANONST) && target <= (ANONEND) ) {
	OutFile << tid << " RET-T " << hex << eip << " " << target << " " << sp << endl;
   }
*/
    if (sp_iter == (*tdata).end()) {
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


	OutFile << tid << hex << "ret address not found!! " << sp << " " << *((*tdata).begin())
	    << " " << target << " " << eip << " "<<targetName << " " << retName << " " << tR << " " << rR << endl;

    	//cout << "RET FROM RET-2" << tid <<endl;
	return;
    }

    if (sp_iter != (*tdata).begin())
	OutFile << hex <<"ret address not in the beginning!! " << target <<" "<< eip << " " << sp <<  " " << *((*tdata).begin()) << " " << dec << dep<< endl;

//    depth -= distance((*tdata).begin(), sp_iter) + 1;
      depth -= dep;

//    OutFile << "Distance " << distance(RetAddrLocs.begin(), sp_iter)  << endl;
//    for (int i=0; i < depth; i++) cerr << " ";
//    cerr << hex << tid << " ret " << sp <<  " " << target << endl;
//    if ( sp_iter == RetAddrLocs.begin() ) {
//	RetAddrLocs.erase(sp_iter);
//	return;
//    }

    (*tdata).erase((*tdata).begin(), sp_iter);
    (*tdata).erase(sp_iter);
    //cout << "RET FROM RET-3" << tid<<endl;
}

VOID Call(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip)
{
//    //cout << "CALL " << tid << hex << " " << sp << " " << target << " " << eip << endl;
//    return;
//    for (int i=0; i < depth; i++) cerr << " ";
//    cerr << hex << tid << " call " << sp << " " << target << endl;
    

    list <ADDRINT> *tdata = data_ar[tid];
    (*tdata).push_front(sp);
    depth++;
    
    if ( target == ( start+FF64PLT ) ) {
	OutFile << tid << " C-PLT64 " << hex << eip << " " <<  target << " " << sp <<  endl;
    }
    if ( eip >= (start+FFI_CALL_UNIX64) && eip <= (start+FF64END) ) {
	OutFile << tid << " C-FF64 " << hex << eip << " " << target << " " << sp << endl;
    }
/*   

   if ( eip >= (ANONST) && eip <= (ANONEND) ) {
	OutFile << tid << " CALL-I " << hex << eip << " " << target << " " << sp << endl;
   }
   if ( target >= (ANONST) && target <= (ANONEND) ) {
	OutFile << tid << " CALL-T " << hex << eip << " " << target << " " << sp << endl;
   }
*/

}

VOID MemWrite(THREADID tid, ADDRINT ea)
{
    list<ADDRINT> *tdata = data_ar[tid];

    list<ADDRINT>::const_iterator sp_iter;// = (*tdata).find(sp);

    for (sp_iter = (*tdata).begin(); sp_iter != (*tdata).end(); sp_iter++) {
	if ( *sp_iter == ea )
	    break;
    }

    if ( sp_iter != (*tdata).end() )
	OutFile << tid << hex << "return address overwrite!!! " << ea << endl;
    //cout << "RET FROM MEWRITE" << tid<<endl;
}

VOID Branch( THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip ) {

    if ( target >= (start+FFI_CALL_UNIX64) && (target <= start+FF64END) ) {
	OutFile << tid << " BRANCH" << hex <<" "<< eip << " " <<  target << " " << sp << endl;
	leaflag = true;

	size_t sizeread;
	ADDRINT value;

	PIN_LockClient();

	sizeread = PIN_SafeCopy(&value, (const VOID *)sp, sizeof(uint64_t));

	if ( sizeread != sizeof(uint64_t) )
	    OutFile << "Incorrect Size read from stack for sp: " << hex << sp << " " << sizeread << endl;
	else 
	    OutFile << tid << " Stack " << hex << sp << " Val " << value << endl;

	PIN_UnlockClient();

    }

    if ( target == (start+FF64PLT) ) 
	OutFile << tid << " J-PLT64 " << hex <<" "<< eip << " " <<  target << " " << sp << endl;

    if ( eip >= (start+FFI_CALL_UNIX64) && eip <= (start+FF64END) ) {
	OutFile << tid << " J-FF64 " << hex << eip << " " << target << " " << sp << endl;

    }




    // Reading value on threads stack



/*
   if ( eip >= (ANONST) && eip <= (ANONEND) ) {
	OutFile << tid << " BRANCH-I " << hex << eip << " " << target << " " << sp << endl;
   }
   if ( target >= (ANONST) && target <= (ANONEND) ) {
	OutFile << tid << " BRANCH-T " << hex << eip << " " << target << " " << sp << endl;
   }
*/
}

VOID ImageLoad(IMG img, VOID *v)
{
    if ( IMG_Name(img) == TARLIB ) {
//	cout << IMG_Name(img) << " " << hex << IMG_LowAddress(img) << " " << IMG_HighAddress(img) << " "
//	    << IMG_NumRegions(img) << endl;
	start = IMG_LowAddress(img);
	end = IMG_HighAddress(img);
	Stat << hex << start << ":" << end << endl;
	cout << hex << start << ":" << end <<" "<< (start + FFI_CALL_UNIX64) << " " << (start+FF64END) <<  endl;
    }
    Stat << hex << IMG_Name(img) << " " << IMG_LowAddress(img) << " " << IMG_HighAddress(img) << " " <<endl;// IMG_NumRegions(img) << endl;
}


VOID ThreadStart( THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    ADDRINT rsp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
    ADDRINT eip = PIN_GetContextReg(ctxt, REG_INST_PTR);
    
   OutFile << dec << tid << hex<< " NTH " << eip << " " << rsp << endl;
}



VOID LeaAdd(THREADID tid, ADDRINT sp, ADDRINT eip, ADDRINT bp ) 
{
    size_t sizeread1, sizeread2, sizeread3;
    ADDRINT value, bpval, bp18 = bp + 0x18, bp18val;

    PIN_LockClient();

    sizeread1 = PIN_SafeCopy(&value, (const VOID *)sp, sizeof(uint64_t));
    sizeread2 = PIN_SafeCopy(&bpval, (const VOID *)bp, sizeof(uint64_t));
    sizeread3 = PIN_SafeCopy(&bp18val, (const VOID *)bp18, sizeof(uint64_t));

    if ( sizeread1 != sizeof(uint64_t) || sizeread2 != sizeof(uint64_t) || sizeread3 != sizeof(uint64_t) )
	OutFile << "Incorrect Size read from stack for sp: " << hex << sp << " " << sizeread1 << " " << sizeread2 << endl;
    else 
	OutFile << tid << " Stack " << hex << sp << " Val " << value << " BP " << bp << " BPVAL " << bpval << 
	    " BP+18 " << bp18 <<" Valbp+18 " << bp18val << endl;

    PIN_UnlockClient();

    OutFile << dec << tid << " LEA " << hex << eip << " " << sp << " "<< bp << endl;
}

VOID Instruction(INS ins, VOID *v)
{
    //if (RTN_Valid(INS_Rtn(ins)) && RTN_Name(INS_Rtn(ins)) == "__SEH_epilog4") {
    //	cerr << "image " << IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) << endl;
    //}

    if ( leaflag && INS_IsLea(ins) ) {

	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(LeaAdd), 
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_STACK_PTR,
		IARG_INST_PTR,
		IARG_REG_VALUE, REG_GBP,
		IARG_END);
    }

    if ( INS_IsBranch(ins) && !(INS_IsCall(ins)) && !(INS_IsRet(ins)) ) {

	INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(Branch), 
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_STACK_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_END);
    }

    else if (INS_IsRet(ins)) {

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


VOID Fini(INT32 code, VOID *v)
{
//    int i;
    Stat << "DUMP Count DS" << endl;

   for (UINT32 i = 0; i < MAX_THREADS; i++)
	Stat << icount[i] << endl;
    Stat << "TID = " << my_tid;
/*
    for ( i  = 0; i < MAX_THREADS; i++) {
	OutFile[i].close();
	delete(data_ar[i]);
    } 
*/
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
    int i = 0;
    stringstream fn;
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
	return 1;
    
    for (i = 0; i<MAX_THREADS; i++) {
//	fn.str("");
//	fn << "cnt.out" << i;
//	OutFile[i].open(fn.str().c_str());
	data_ar[i] = new list<ADDRINT>();
    }

    OutFile.open(OUT_FILE);
      Stat.open(STAT_FILE);
//    CallFile.open(CALL_FILE);


    // Register ThreadStart to be called when a thread starts.
//    PIN_AddThreadStartFunction(ThreadStart, 0);

    TRACE_AddInstrumentFunction(Trace, 0);

    IMG_AddInstrumentFunction(ImageLoad, 0);

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
