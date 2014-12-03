#include <iostream>
#include <fstream>
#include <sstream>
#include <assert.h>
#include <stdint.h>

#define COUNT 112

#define ROOT_PATH "/var/services/homes/adabral/elider/pintools/asplos/"
#define RANGE_PATH ROOT_PATH "/finalrange.out"
#define SPLIT_PATH ROOT_PATH "/ranges"	

using namespace std;

int main()
{
    stringstream tmp;
    uint64_t a1, a2;
    int i;

    std::ofstream dumpplt;
    std::ifstream rangestream;

    dumpplt.open(RANGE_PATH, ios::out | ios::binary );

    for ( i = 0; i < COUNT; i++ ) {
	a1 = 0;
	a2 = 0;

	tmp.str("");
	tmp << SPLIT_PATH << i << ".out";

	rangestream.open( tmp.str().c_str(), ios::in | ios::binary );

	rangestream.read((char *)&a1, 8);
	rangestream.read((char *)&a2, 8);

	dumpplt.write((char *)&a1, 8);
	dumpplt.write((char *)&a2, 8);

	rangestream.close();
    }

    dumpplt.close();
    return 0;
}


