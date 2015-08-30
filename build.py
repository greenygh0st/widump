#!/usr/bin/env python

import os
import sys

def uninstall_parts(package):
	import shutil
	#sys.prefix
	loc=os.sep.join([sys.prefix, 'lib', 'python' + sys.version[:3], 'site-packages', package]) #try sys.prefix
	if os.path.exists(loc):
		print 'Removing files from ' + loc
		shutil.rmtree(loc,ignore_errors=False)
	loc=os.sep.join([sys.prefix, 'lib', 'python' + sys.version[:3], 'dist-packages', package]) #try dist-packages
	if os.path.exists(loc):
		print 'Removing files from ' + loc
		shutil.rmtree(loc,ignore_errors=False)

	#/usr/local
	loc=os.sep.join(['/usr/local', 'lib', 'python' + sys.version[:3], 'site-packages', package]) #try sys.prefix
	if os.path.exists(loc):
		print 'Removing files from ' + loc
		shutil.rmtree(loc,ignore_errors=False)
	loc=os.sep.join(['/usr/local', 'lib', 'python' + sys.version[:3], 'dist-packages', package]) #try dist-packages
	if os.path.exists(loc):
		print 'Removing files from ' + loc
		shutil.rmtree(loc,ignore_errors=False)

	if os.path.exists('/usr/local/bin/' + package):
		print 'Removing file: /usr/local/bin/' + package
		try: os.remove('/usr/local/bin/' + package)
		except: pass
	if os.path.exists('/usr/bin/' + package):
		print 'Removing file: /usr/bin/' + package
		try: os.remove('/usr/bin/' + package)
		except: pass
	if os.path.islink('/usr/bin/' + package):
		print 'Removing link: /usr/bin/' + package
		try: os.remove('/usr/bin/' + package)
		except: pass

	#binary

if 'uninstall' in sys.argv:
	uninstall_parts('authwatch')
	print 'Uninstall complete'
	sys.exit(0)


#INSTALL IT
from distutils.core import setup
s = setup(name='widump',
	version='1.0',
	description='',
	license='MIT',
	author='Dale Myszewski',
	author_email='dale.myszewski@gmail.com',
	url='http://daleslab.com',
	requires = ['scapy'],
	packages=['widump'],
	package_dir={'widump': ''},
	scripts=['widump']
	)
