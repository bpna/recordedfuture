z = open("zeek_intel.txt", 'r')
d = open("watchlist.file", "r")

zs = []
ds = []

for line in z.readlines():
    x = line.split()
    zs.append(x[0])

for line in d.readlines():
    x = line.split()
    ds.append(x[1])

for z in zs:
    if z in ds:
        print('matched IP ' + z)
