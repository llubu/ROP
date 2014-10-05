#include <iostream>
#include <fstream>
#include <set>

#include "pin.H"

#define MAX_THREADS 512
#define OUT_FILE "cnt.out"

ofstream OutFile;
static UINT64 icount[MAX_THREADS] = {0};
set<ADDRINT> RetAddrLocs;
UINT64 my_tid = 0;

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
    set<ADDRINT>::const_iterator sp_iter = RetAddrLocs.find(sp);

    if (push) {
	OutFile << "PUSH FOUND" << endl;
	RetAddrLocs.erase(RetAddrLocs.begin());
	return;
    }
    if (sp_iter == RetAddrLocs.end()) {
	//		cerr << hex << "ret address not found!! " << sp << " " << *(RetAddrLocs.begin())
	OutFile << tid << hex << "ret address not found!! " << sp << " " << *(RetAddrLocs.begin())
	    << " " << target << " " << eip << endl;
	return;
    }

//    if (sp_iter != RetAddrLocs.begin())
//	OutFile << "ret address not in the beginning!! " << endl;

    depth -= distance(RetAddrLocs.begin(), sp_iter) + 1;
//    OutFile << "Distance " << distance(RetAddrLocs.begin(), sp_iter)  << endl;
//    for (int i=0; i < depth; i++) cerr << " ";
//    cerr << hex << tid << " ret " << sp <<  " " << target << endl;
//    if ( sp_iter == RetAddrLocs.begin() ) {
//	RetAddrLocs.erase(sp_iter);
//	return;
//    }

//    RetAddrLocs.erase(RetAddrLocs.begin(), sp_iter);
//    RetAddrLocs.erase(sp);
}

VOID Call(THREADID tid, ADDRINT sp, ADDRINT target, ADDRINT eip)
{
//    cout << "CALL " << tid << hex << " " << sp << " " << target << " " << eip << endl;
//    return;
//    for (int i=0; i < depth; i++) cerr << " ";
//    cerr << hex << tid << " call " << sp << " " << target << endl;
    RetAddrLocs.insert(sp);
    depth++;
}

VOID MemWrite(THREADID tid, ADDRINT ea)
{
    if (RetAddrLocs.find(ea) != RetAddrLocs.end())
	OutFile << "return address overwrite!!!" << endl;
}


VOID Instruction(INS ins, VOID *v)
{
    //if (RTN_Valid(INS_Rtn(ins)) && RTN_Name(INS_Rtn(ins)) == "__SEH_epilog4") {
    //	cerr << "image " << IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) << endl;
    //}

    if (INS_IsRet(ins)) {

	INS prev = INS_Prev(ins);

	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Ret),
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_ESP,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_UINT32, (INS_Valid(prev) && INS_Opcode(prev) == XED_CATEGORY_PUSH),
		IARG_END);

    }
    else if (INS_IsCall(ins))

	INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(Call),
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_ESP,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_END);

    else if (INS_IsMemoryWrite(ins))

	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(MemWrite),
		IARG_THREAD_ID,
		IARG_MEMORYWRITE_EA,
		IARG_END);
}


VOID Fini(INT32 code, VOID *v)
{
    OutFile << "DUMP Count DS" << endl;

    for (UINT32 i = 0; i < MAX_THREADS; i++)
	OutFile << icount[i] << endl;
    OutFile << "TID = " << my_tid;

    OutFile.close();

    cerr << "SIZE" << RetAddrLocs.size() << endl;

    //	for (auto ea : RetAddrLocs)
    //	set<ADDRINT>::const_iterator ret_iter;
    //	for ( ret_iter = RetAddrLocs.begin(); ret_iter != RetAddrLocs.end(); ret_iter++ ) 
    //		cerr << hex << *ret_iter<< endl;
}


int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
	return 1;

    OutFile.open(OUT_FILE);

    TRACE_AddInstrumentFunction(Trace, 0);

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
