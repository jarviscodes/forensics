import sys
import struct
import volatility.conf as conf
import volatility.registry as registry
import volatility.win32.rawreg as rawreg

memory_file = sys.argv[1]

registry.PluginImporter()
config = conf.ConfObject()

import volatility.commands as commands
import volatility.addrspace as addrspace

config.parse_options()
config.PROFILE = "Win7SP1x86_23418"
config.LOCATION = "file://%s" % memory_file

registry.register_global_options(config,commands.Command)
registry.register_global_options(config,addrspace.BaseAddressSpace)

from volatility.plugins.registry.registryapi import RegistryApi

registry = RegistryApi(config)
registry.populate_offsets()

sys_offset = None

for offset in registry.all_offsets:
	if registry.all_offsets[offset].endswith("\\SYSTEM"):
		sys_offset = offset
		print "[*] Found SYSTEM offset at: 0x%08x" % offset
		break

if sys_offset is None:
	print "[!] Error finding SYSTEM offset."
	exit()
from volatility.plugins.registry.printkey import PrintKey

config.HIVE_OFFSET = sys_offset
config.KEY= "ControlSet001\\Control\\ComputerName\\ComputerName"

hostnamekey = PrintKey(config)
for name, key in hostnamekey.calculate():
	if key is not None:
		for v in rawreg.values(key):
			if v.Name == "ComputerName":
				computername=key.obj_vm.read(v.Data, v.DataLength).decode('utf-16-le')
				print "[*] Found hostname: %s" % computername
	
	