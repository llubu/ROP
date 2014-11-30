import re

pin = open("/var/services/homes/adabral/elider/pintools/link/pltpinCount.out", "r")
gdb = open("/var/services/homes/adabral/elider/pintools/link/gdbCount.out", "r")

glines = gdb.readlines()
plines = pin.readlines()

data = dict()
matchCount = 0
pcount = 0
gcount = 0

for line in glines:
    gcount += 1
    tmp = line.split(' is .plt in ')
    add = tmp[0]
    lib = tmp[1].split('\n')[0]

    tmpadd = add.split(' - ')
    t1 = int(tmpadd[0], 16)
    t2 = int(tmpadd[1], 16)
#    print t1, t2

    if lib in data:
	print "Double Hit Error", line, data[(t1,t2)]
    else:
	data[lib] = (t1, t2)

libmatch = 0
for line in plines:
    pcount += 1
    tmp = line.split('@')
    add = tmp[0]
    lib = tmp[1].split('\n')[0]

    tmpadd = add.split(':')
    t1 = int(tmpadd[0], 16)
    t2 = int(tmpadd[1], 16)
#    print t1, t2
    
    if lib in data:
	if (t1, t2) != data[lib]:
	    libmatch += 1
	    print 'plt area mismatch- Lib match'
	    print 'From GDB', lib, hex(data[lib][0]), hex(data[lib][1])
	    print 'From PIN', hex(t1), hex(t2), '\n'
	else:
	    matchCount += 1
    else:
	print 'NOT FOUND', hex(t1), hex(t2), lib


print 'PIN COUNT: ', pcount, 'Gdb Count: ', gcount, 'Match Count: ', matchCount, 'Lib Match: ', libmatch


pin.close()
gdb.close()

