import re

fi = open("/var/services/homes/adabral/elider/pintools/link/gdb.txt", "r")
op = open("/var/services/homes/adabral/elider/pintools/link/gdbCount.out", "w")

data = fi.readlines()

for line in data:
    tmp = line.split('is')

    try:
	if None != re.match(r" .plt", tmp[1]):
	    op.write(line)
    except IndexError:
	print line


fi.close()
op.close()




