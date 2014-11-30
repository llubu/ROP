
fi = open("C:\Users\dZONE\Desktop\plt.txt", "r")

da = fi.readlines()
plt = list()

i = 0
for line in da:
	if ".plt" in line:
		i += 1
		tmp = line.split('is')[0]
		tmp1 = tmp.split('-')
		#print line, i, tmp
		print tmp, tmp1
		
		plt.append(int(tmp1[0], 16))
		plt.append(int(tmp1[1], 16))
		
(sorted(plt, key=int))

for item in plt:
	print hex(item)