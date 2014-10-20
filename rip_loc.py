#to find where the rips lies in ff memory map

# ********************* SET PATH BEFORE USING THE SCRIPT DONT OVERWRITE CURRENT LOG FILES-MAKE A NEW FOLDER *******************************

mapf = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\ff.map", "r")
log = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\log.out", "r") #Parsed file from stat.py only contains ret address not found log lines

rip_loc = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\rip.out", "w")  # Contains all mappings with RIP in them.
fileb = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\fileb.out", "w")  # Contains log file with RIP in file backed mappings
fmap = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\mapping.out", "w")  # Contains log file with target and RIP mappings
log_lines = log.readlines()
map_lines = mapf.readlines()
i = 0
j = 0
for line in log_lines:
	i += 1
	tmp1 = line.split('\n')
	tmp = tmp1[0].split(' ')
	try:
		pc = int(tmp[7], 16)     # RIP in ff.out
	except IndexError:
		print "Index Error",line, i
	for map in map_lines:
		mapl = map.split(' ')
		mapl = mapl[0].split('-')
		start = int(mapl[0], 16)	# mapped range in ff.map
		end = int(mapl[1], 16)
		if (pc > start and pc < end):
			#print line, "***", mapl
			if "var" in map:		# The PC lies in some file backed mem region in FF.map
				j += 1
				#print tmp1[0], "***", map
				fileb.write( tmp1[0]+ "***" + map)	
			rip_loc.write(tmp1[0] + "***" + map)
			
print " TOTAL FILE BACKED MAPPINGS:", j
rip_loc.close()
mapf.close()
log.close()
fileb.close()