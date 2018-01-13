import sys
import struct
import volatility.conf as conf
import volatility.registry as registry

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
from volatility.plugins.registry.lsadump import HashDump

registry = RegistryApi(config)
registry.populate_offsets()