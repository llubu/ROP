mapf = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\ff.map", "r")
fileb = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\fileb.out", "r")
finalOut = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\tarANON.out", "w") 
mymap = open("C:\Users\dZONE\Desktop\ROP\\10-18-14\wtotGDB\\mapping.out", "w")  # Contains log file with target and RIP mappings

map_lines = mapf.readlines()
file_lines = fileb.readlines()
j = 0
for line in file_lines:
	j += 1
	tmp1 = line.split('\n')
	tmp = tmp1[0].split('***')[0]
	tmp = tmp.split(' ')
	target = int(tmp[6], 16) # Branch target addr in ff.map
	for maptar in map_lines:		# Now check if any target from such mapping falls in anon region
		mapt = maptar.split(' ')
		mapt = mapt[0].split('-')
		start = int(mapt[0], 16)
		end = int(mapt[1], 16)
		if ( target > start and target < end ):
			if "var" in maptar:
				continue
			else:
				#pass
				print j, hex(target), maptar
				finalOut.write(tmp1[0] + "***" +maptar)
			mymap.write(tmp1[0] + "***" + maptar)
			
				
				
mapf.close()
fileb.close()
finalOut.close()
mymap.close()