# OutFile << tid << hex << "ret address not found!! " << sp << " " << *((*tdata).begin())<< " " << target << " " << eip << endl;
# 0ret address not found!! ad8d38a8 ad8d38c8 7f9184043e08 7f9184041b4e
# sp = 4 top =5 target = 6 rip =7

import operator

# ********************* SET PATH BEFORE USING THE SCRIPT DONT OVERWRITE CURRENT LOG FILES-MAKE A NEW FOLDER *******************************

file = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\cnt.out", "r")  #log file from pin tool
op_file = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\fox_out1.out", "w") #Parses all ret address not in begining target rip
tar_file = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\fox_tar1.out", "w") #contains target and frequency
log = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\log.out", "w") #Parses all ret address not found in a seprate logfile
brlog = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\branch.out", "w") # Contains all branch to required region

lines = file.readlines()
lastBranch = 0
sp = dict()
top = dict()
target = dict()
rip = dict()
min_rip = float("inf")
i = 0
branchcount = 0
for line in lines:
	i += 1 
	#print i, " &&&" ,line
	tmp = line.split('\n')[0]
	tmp = tmp.split(' ')
	if tmp[0] == 'ret':
		op_file.write(line)
		continue
	else:
		pass
		log.write(line)
	try:
		if tmp[1] == 'BRANCH':
			branchcount += 1
			brlog.write(line)
			if lastBranch == (i -1):
				brlog.write('\n')
			lastBranch = i
			continue
	except IndexError:
		print i, tmp
	

	try:
		if tmp[2] != 'not':
			print "BREAK MET", i
			print tmp
			break
	except IndexError:
		print i, tmp
	try:
		if tmp[12]:
			print "LONF STR"
			print i, tmp
			break
	except IndexError:
		pass
	
	if tmp[4] in sp:
		sp[tmp[4]] += 1
	else:
		sp[tmp[4]] = 1
	if tmp[5] in top:
		top[tmp[5]] += 1
	else:
		top[tmp[5]] = 1
	try:
		if tmp[6] in target:
			target[tmp[6]] += 1
		else:
			target[tmp[6]] = 1
	except IndexError:
		print i, tmp
	try:
		if tmp[7] in rip:
			rip[tmp[7]] += 1
		else:
			rip[tmp[7]] = 1
	except IndexError:
		print i, tmp
		
	"""
	if (int(tmp[7], 16) < 0x600000):
		print "FireFox Binary RIP", temp[7]
		
	if int(tmp[7], 16) < min_rip:
		min_rip = int(tmp[7], 16)
		print min_rip, hex(min_rip)
		"""

print "Branch Count: " , branchcount
op_file.close()
log.close()
len = 0
tar = list()
brlog.close()

#target -MAX '7fffa2e98934', 669)
#RIP -MAX ('7fffc61ba976', 8839)
#sp -MAX ('ffff6d50', 609)
#top -MAX ('ffff6d98', 613)
	
#ma = max(top.iteritems(), key=operator.itemgetter(1))
#print ma 

for item in target:
		#print target[item], item
		tar_file.write(item)
		tar_file.write(' ')
		tar_file.write(str(target[item]))
		tar_file.write('\n')
tar_file.close()

	
			
		
	#print "SP", sp
	#print "TOP", top
	#print "Target", target
	#print "RIP", rip