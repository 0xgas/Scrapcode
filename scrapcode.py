#!/usr/bin/python3

import sys
import os
import re
from threading import Thread,RLock

filelist=list()
ext=""
search_patterns=list()
vulnlist=list()
lock=RLock()

thr_num=50

class Worker(Thread):
	def __init__(self, name):
		Thread.__init__(self)
		self.name=name

	def run(self):
		while True:
			with lock:
				if len(filelist) > 0:
					f=filelist[0]
					filelist.pop(0)
				else:
					return
			self.scanfile(f)
		
	def scanfile(self, f):
		with open(f, "r") as of:
			with lock:
				print("[\033[94m*\033[0m] {%s} Scanning file %s ..." % (self.name, f))
			i=0
			for line in of:
				i+=1
				for p in search_patterns:
					m=re.search(r'%s' % p, line)
					if m:
						with lock:
							vulnlist.append(("\033[91m%s\033[0m>\033[94m%s:\033[92m%d\033[0m> %s" % (p, f, i, "..."+line[line.index(m.group(0)):])).replace('\n',''))

def main():
	if len(sys.argv) != 3:
		usage()
		return
	patfile=str(sys.argv[1])
	path=str(sys.argv[2])
	(ext, search_patterns)=get_patterns(patfile)
	print("[\033[92m*\033[0m] Scanning root dir %s ..." % path)
	scandir(path, ext)
	print("[\033[92m*\033[0m] %d files ready to be scanned." % len(filelist))
	threads=list()
	try:
		for t in range(thr_num):
			t=Worker("thr"+str(t+1))
			t.setDaemon(True)
			t.start()
			threads.append(t)
	except KeyboardInterrupt:
		print "[\033[91m!\033[0m] Ctrl-c, Exiting..."
		sys.exit()
	
	threads = [t.join(1000) for t in threads if t is not None and t.isAlive()]

	for vuln in vulnlist:
		print vuln
	return

def scandir(rootdir, ext):
	for root,subfolders,files in os.walk(rootdir):
		if root[-1] != '/':
			root=root+'/'
		for f in files:
			if f[(len(ext)*-1):] == ext:
				filelist.append(root+f)
		for sf in subfolders:
			scandir(root+sf, ext)
	

def get_patterns(patfile):
	i=0
	for line in open(patfile, "r").readlines():
		if i==0:
			ext=line.split(':')[1].strip()
		else:
			search_patterns.append(line.replace("\n",""))
		i+=1
	return (ext, search_patterns)

def usage():
	print("Usage:")
	print("%s <path_to_src_code>" % sys.argv[0])
	return
	

if __name__=='__main__':
	main()
