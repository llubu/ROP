#include <iostream>
#include <fstream>
#include <list>

#include "pin.H"

#define MAX_THREADS 512
#define OUT_FILE "cnt.out"
#define CALL_FILE "call.out"

ofstream OutFile;
ofstream CallFile;

static UINT64 icount[MAX_THREADS] = {0};
//list<ADDRINT> RetAddrLocs;
UINT64 my_tid = 0;
list<ADDRINT> *data_ar[MAX_THREADS];

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
    list<ADDRINT> *tdata = data_ar[tid];
    list<ADDRINT>::iterator sp_iter;// = (*tdata).find(sp);
    list<ADDRINT>::iterator dep_iter;// = (*tdata).find(sp);

    for (sp_iter = (*tdata).begin(); sp_iter != (*tdata).end(); sp_iter++) {
	++dep;
	if ( *sp_iter == sp )
	    break;
    }

    if (push) {
	OutFile << "PUSH FOUND" << endl;
	(*tdata).erase((*tdata).begin());
    	//cout << "RET FROM RET-1" << tid<<endl;
	return;
    }
    if (sp_iter == (*tdata).end()) {
	//		cerr << hex << "ret address not found!! " << sp << " " << *(RetAddrLocs.begin())
	OutFile << tid << hex << "ret address not found!! " << sp << " " << *((*tdata).begin())
	    << " " << target << " " << eip << endl;

    	//cout << "RET FROM RET-2" << tid <<endl;
	return;
    }

    if (sp_iter != (*tdata).begin())
	OutFile << hex <<"ret address not in the beginning!! " << target<<endl;

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
    CallFile << hex << sp << " " << target << " " << eip << endl;
    //cout << "RET from CALL" << tid <<endl;
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
	OutFile << "return address overwrite!!!" << endl;
    //cout << "RET FROM MEWRITE" << tid<<endl;
}


VOID Instruction(INS ins, VOID *v)
{
    //if (RTN_Valid(INS_Rtn(ins)) && RTN_Name(INS_Rtn(ins)) == "__SEH_epilog4") {
    //	cerr << "image " << IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) << endl;
    //}

    if (INS_IsRet(ins)) {

	INS prev = INS_Prev(ins);
	//cout<< "CALL TO RET" << endl;

	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Ret),
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_ESP,
		IARG_BRANCH_TARGET_ADDR,
		IARG_INST_PTR,
		IARG_UINT32, (INS_Valid(prev) && INS_Opcode(prev) == XED_CATEGORY_PUSH),
		IARG_END);

    }
    else if (INS_IsCall(ins)) {
	//cout << "CALL TO CALL" << endl;

	INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(Call),
		IARG_THREAD_ID,
		IARG_REG_VALUE, REG_ESP,
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
    OutFile << "DUMP Count DS" << endl;

    for (UINT32 i = 0; i < MAX_THREADS; i++)
	OutFile << icount[i] << endl;
    OutFile << "TID = " << my_tid;

    OutFile.close();
    CallFile.close();

//    cerr << "SIZE" << RetAddrLocs.size() << endl;

    //	for (auto ea : RetAddrLocs)
    //	list<ADDRINT>::const_iterator ret_iter;
    //	for ( ret_iter = RetAddrLocs.begin(); ret_iter != RetAddrLocs.end(); ret_iter++ ) 
    //		cerr << hex << *ret_iter<< endl;
}


int main(int argc, char * argv[])
{
    int i = 0;
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
	return 1;
    for (i = 0; i<MAX_THREADS; i++)
	data_ar[i] = new list<ADDRINT>();

    OutFile.open(OUT_FILE);
    CallFile.open(CALL_FILE);

    TRACE_AddInstrumentFunction(Trace, 0);

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
