from optparse import OptionParser
import os, sys, traceback
import errno
import time
import re

USER_DELAY = 0.0

def get_options(parser):
	
	# http://docs.python.org/2/library/optparse.html
	#usage = "usage: %prog [options] arg"
	#parser = OptionParser(usage)
	
	#parser.add_option('-n', "--nsamples", action="store", dest="nsamples", type="int", help='number of samples in FILENAME')
	
	parser.add_option("--vginstdir", 
					action='store',
					dest='vginstdir',
					default = None, 
					help='the Valgrind installation directory to use to configure Capstone')
    
	parser.add_option("--capstonedir", 
					action='store',
					dest='capstonedir',
					default = None, 
					help='the Capstone directory containing the source code')
	
	parser.add_option("--outmakefile", 
					action='store',
					dest='outmakefile',
					default = None, 
					help='the Capstone makefile to output')
				
	parser.add_option("--arch", 
					action='store',
					dest='arch',
					default = None, 
					help='architecture to build')
				
	parser.add_option("-v", "--verbose",
					action="store_true", 
					dest="verbose")
	
    
	return parser.parse_args()


def check_options(parser, options, args):
	
	if options.vginstdir == None:
		parser.error("VGINSTDIR not supplied")
	
	if options.capstonedir == None:
		parser.error("CAPSTONEDIR not supplied")
		
	if options.outmakefile == None:
		parser.error("OUTMAKEFILE not supplied")

def silentremove(filename):
	try:
		os.remove(filename)
	except OSError as e: # this would be "except OSError, e:" before Python 2.6
		if e.errno != errno.ENOENT: # errno.ENOENT = no such file or directory
			raise # re-raise exception if a different error occured

def append_tailing_slash(indir):
	if indir[-1] != '/':
		indir += '/'
	return indir

def readfromfile(filename):
	with open(filename, "r") as f:
		return f.read()
	
def save2file(content, filename):
	with open(filename, "w") as f:
		f.write(content)
	
def main(options):
	
	vginstdir = os.path.realpath(options.vginstdir)
	capstonedir = os.path.realpath(options.capstonedir)
	outmakefile = options.outmakefile
        arch = options.arch
		
	# folders exists?
	if not os.path.isdir(vginstdir):
		raise Exception("folder '%s' does not exist" % vginstdir)
		
	if not os.path.isdir(capstonedir):
		raise Exception("folder '%s' does not exist" % capstonedir)
	
	# add tailing slash if need be
	vginstdir = append_tailing_slash(vginstdir)
	capstonedir = append_tailing_slash(capstonedir)

	# folder looks like valgrind installation folder?
	vginstdir_incval = vginstdir + "include/valgrind/"
	
	if not os.path.isdir(vginstdir_incval):
		raise Exception("'include/valgrind/' missing from folder '%s'. Was Valgrind compiled and installed in this folder?" % vginstdir)
	
	flags = "VGO_linux=1 VGA_" + arch + "=1"
	
	# file content. 
	# originally I used this to install. I've changed to a simple copy so it does not require root
	# sudo %s CAPSTONE_BUILD_CORE_ONLY=yes CAPTSTONE_SECRETGRIND_HEADER_DIR=%s CAPSTONE_STATIC=yes CAPSTONE_SHARED=no ./make.sh install
	# no longer copy the lib*.a
	# no longer copy the header files

	content = """

#!/bin/sh
		
# WARNING: this was auto-generated. Do not change!!!

# build static libs only		
%s CAPSTONE_BUILD_CORE_ONLY=yes CAPTSTONE_SECRETGRIND_HEADER_DIR=%s CAPSTONE_STATIC=yes CAPSTONE_SHARED=no ./make.sh

	""" % (flags, vginstdir_incval)

        # Special case: If we're cross-compiling x86 on amd64
        import platform
        if arch == "x86" and "x86_64" in platform.platform():
            content = content.replace("make.sh", "make.sh nix32")

	#print content
	
	# save the file
	outmakefile = capstonedir + outmakefile
	silentremove(outmakefile)
	save2file(content, outmakefile)
	
	# create the symbolic link
	silentremove("../include/capstone")
	os.symlink(capstonedir + "include/", "../include/capstone")
	
	# create the file that we'll use for building capstone with the correct options
	# CAPSTONE_ARCHS="arm aarch64 x86" TODO
	# CAPSTONE_COMPILE_TEMPLATE
		
if __name__ == '__main__':
		
	parser = OptionParser()
	(options, args) = get_options(parser)
	check_options(parser, options, args)
	ret = 0
	
	main(options)

	sys.exit(ret)
	
	
