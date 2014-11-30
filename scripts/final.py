mapf = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\ff.map", "r")
fileb = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\fileb.out", "r")
#finalOut = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\FB_ANON.out", "w") # Contains mapping from RIP in FB and target in ANON region
#mymap = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\mapping.out", "w")  # Contains log file with target and RIP mappings
anonb = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\anonb.out", "r")  # Contains log file with RIP in ANON REGION
anonout = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\ANON_FB.out", "w") # Contains mapping from RIP in ANON and target in FB region
anonAOut = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\ANON_ANON.out", "w") # Contains mapping from RIP in ANON and target in ANON region
#fbfb = open("C:\Users\dZONE\Desktop\ROP\\11-25-14\ANON\\FB_FB.out", "w") # Contains mapping from RIP in FB and target in FB region

map_lines = mapf.readlines()
file_lines = fileb.readlines()
anonr = anonb.readlines()

#0ret address not found!! ffff4d40 ffff4d60 7fffbbe5d433 7fffbbe56bfe ANON ANON  ***7fffbbc55000-7fffbbf00000 rwxp 00000000 00:00 0 

j = 0
k = 0

for line in anonr: # Change depending on which mapping FB->ANON or ANON->FB is needed
	j += 1
	tmp1 = line.split('\n')
	tmp = tmp1[0].split('***')[0]
	tmp = tmp.split(' ')
	target = int(tmp[6], 16) # Branch target addr in Pin Log
	for maptar in map_lines:		# Now check if any target from such mapping falls in anon/FB region
		mapt = maptar.split(' ')
		mapt = mapt[0].split('-')
		start = int(mapt[0], 16)
		end = int(mapt[1], 16)
		if ( target > start and target < end ):
			if "var" in maptar or "lib" in maptar: #if Target in File Backed region
				k += 1
				anonout.write(tmp1[0] + "***" + maptar)
				#fbfb.write(tmp1[0] + "***" + maptar)
				#print k, tmp1[0], maptar
			else:  # If target in Anon region 
				#pass
				#print j, hex(target), maptar
				#finalOut.write(tmp1[0] + "***" + maptar)
				anonAOut.write(tmp1[0] + "***" + maptar)
			#mymap.write(tmp1[0] + "***" + maptar) # Contains all the mappings
			
				
				
mapf.close()
fileb.close()
#fbfb.close()
#finalOut.close()
#mymap.close()
anonb.close()
#anonAOut.close() 
#anonout.close()