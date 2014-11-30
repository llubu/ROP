#to find where the rips lies in ff memory map

# ********************* SET PATH BEFORE USING THE SCRIPT DONT OVERWRITE CURRENT LOG FILES-MAKE A NEW FOLDER *******************************

mapf = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\ff.map", "r")
log = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\log.out", "r") #Parsed file from stat.py only contains ret address not found log lines

rip_loc = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\rip.out", "w")  # Contains all mappings with RIP in them.
fileb = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\fileb.out", "w")  # Contains log file with RIP in file backed mappings
anonb = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\anonb.out", "w")  # Contains log file with RIP in ANON REGION


log_lines = log.readlines()
map_lines = mapf.readlines()
i = 0
j = 0
k = 0
for line in log_lines:
	i += 1
	tmp1 = line.split('\n')
	tmp = tmp1[0].split(' ')
	try:
		pc = int(tmp[7], 16)     # RIP in ff.out
	except (IndexError, ValueError):
		print "Index or Value Error Error-RIP-7",line, i
		break
	for map in map_lines:
		mapl = map.split(' ')
		mapl = mapl[0].split('-')
		start = int(mapl[0], 16)	# mapped range in ff.map
		end = int(mapl[1], 16)
		if (pc > start and pc < end):
			#print line, "***", mapl
			if "lib" in map or "var" in map:		# The PC lies in some file backed mem region in FF.map
				j += 1
				#print tmp1[0], "***", map
				fileb.write( tmp1[0]+ "***" + map)	
			
			else:
				anonb.write(tmp1[0]+ "***" + map)
			rip_loc.write(tmp1[0] + "***" + map)
				
		
			
print " TOTAL FILE BACKED MAPPINGS:", j
rip_loc.close()
mapf.close()
log.close()
fileb.close()
anonb.close()