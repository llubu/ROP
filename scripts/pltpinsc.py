import re

fi = open("/var/services/homes/adabral/elider/pintools/link/pltpin.out", "r")
op = open("/var/services/homes/adabral/elider/pintools/link/pltpinCount.out", "w")

data = fi.readlines()

prevline = ""

for line in data:
    if "Load:" in line:
	prevline = line
    else:
	tmp = line.split('\r\n')[0]
	op.write(tmp + '@')
	tmp = prevline.split('Load: ')[1]
	tmp = tmp.split('\r\n')
	op.write(tmp[0] + '\n')


fi.close()
op.close()
