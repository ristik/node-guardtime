import Utils
import os

APPNAME = 'node-guardtime'
VERSION = '0.0.3'
libgt = 'libgt-0.3.10'

def set_options(opt):
  opt.tool_options("compiler_cxx")

def configure(conf):
  root = os.path.dirname(root_path)
  Utils.exec_command("cd %s/%s/ && CFLAGS=-fPIC ./configure --disable-shared && cd src/base && make && cd ../../.." % (root, libgt))
  # later: conf.sub_config("libgt")
  conf.check_tool("compiler_cxx")
  conf.check_tool("node_addon")

def build(bld):
  root = os.path.dirname(root_path)
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.cxxflags = ["-g", "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE", "-Wall", 
          ("-I%s/%s/src/base" % (root, libgt))]
  obj.linkflags = [("-L%s/%s/src/base/.libs" % (root, libgt))]
  obj.lib = ["gtbase", "crypto"]
  obj.target = "timesignature"
  obj.source = "timesignature.cc"

def test(ctx):
  status = Utils.exec_command('node tests.js')
  if status != 0:
    raise Utils.WafError('tests failed')

def shutdown():
  import Options, shutil
  if not Options.commands['clean']:
    if os.path.exists('build/default/timesignature.node') and not os.path.exists('timesignature.node'):
      os.symlink('build/default/timesignature.node', 'timesignature.node')
  else:
    if os.path.exists('timesignature.node'):
      os.unlink('timesignature.node')
