 #!/usr/bin/python 

fi = open("/var/services/homes/adabral/elider/pintools/link/page.out", "r")
op = open("/var/services/homes/adabral/elider/pintools/link/pageCount.out", "w")

data = fi.readlines()

pg = dict()
i = 0

for line in data:
    i += 1
    tmp = line.split('\n')[0]
    num = int(tmp, 16)
    if num in pg:
        pg[num] += 1
    else:
        pg[num] = 1

print len(pg)
op.write("Unique Pages: " + str(len(pg)) + '\n')
op.write('Total Patch Count: ' + str(i) + '\n')

j = 0
for item in pg:
    j += pg[item]
    op.write(str(hex(item)) + ':' + str(pg[item]) + '\n')

if i != j:
    print 'Wrong'

op.close()
fi.close()
