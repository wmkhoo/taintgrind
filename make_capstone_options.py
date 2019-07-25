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

def get_flags(infile):
	flags = "" # "VGO_linux=1 VGA_amd64=1"
	flagstable = dict()
	
	# read content
	content = readfromfile(infile)
	
	# get VGO flags = OS flags
	vgoList = re.findall(r'-DVGO_[a-z,A-Z,0-9]*=\d', content) # eg -DVGO_linux=1
	for vgo in vgoList:
		flagstable[ vgo[2:] ] = 1

	# get VGA flags = architecture flags
	vgaList = re.findall(r'-DVGA_[a-z,A-Z,0-9]*=\d', content) # eg -DVGA_amd64=1
	for vga in vgaList:
		flagstable[ vga[2:] ] = 1
	
	# get VGP flags. Not sure what they are. We don't really need them at the moment anyway since the compilation works wihtout them
	# I put them anyway...
	vgpList = re.findall(r'-DVGP_[a-z,A-Z,0-9,_]*=\d', content) # eg -DVGP_amd64_linux=1
	for vgp in vgpList:
		flagstable[ vgp[2:] ] = 1
		
	for key in flagstable:
		flags += key + " "
		
	return flags

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
	
	# read the Makefile of Valgrind and extract 
	# - the relevant options to pass to valgrind's headers 
	#		- platform flags :VGA_x86, VGA_amd64, VGA_ppc32, VGA_ppc64be, VGA_ppc64le, VGA_arm, VGA_arm64, VGA_s390x, VGA_mips32, VGA_mips64
	#		- OS flags: ...
	# - the relevant options for capstone itself, so we compile only the platforms we need
	#		(arm, aarch64, mips, powerpc, sparc, systemz, x86, xcore)
	# Well, I've decided it's just simpler to compile it all... TODO
	
	# I extract any flags that looks like -DVGO_***=1, eg -DVGO_linux=1 and -DVGA_***=1
	flags = get_flags("../Makefile")
	
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
	
	
