import os

VERSION = '0.0.1'

def set_options(opt):
  opt.tool_options("compiler_cxx")

def configure(conf):
  os.system('cd libgt && ./configure && make && popd')
  # later: conf.sub_config("libgt")
  conf.check_tool("compiler_cxx")
  conf.check_tool("node_addon")

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.cxxflags = ["-g", "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE", "-Wall", "-Llibgt/src/base/.libs/"]
  obj.lib = ["gtbase", "crypto"]
  obj.target = "timesignature"
  obj.source = "timesignature.cc"

def shutdown():
  import Options, shutil
  if not Options.commands['clean']:
    if os.path.exists('build/default/binding.node'):
      os.symlink('build/default/timesignature.node', 'timesignature.node')
  else:
    if os.path.exists('timesignature.node'):
      os.unlink('timesignature.node')
