import Utils
import os, sys

APPNAME = 'node-guardtime'
VERSION = '0.0.4'
libgt = 'libgt-0.3.10'

def set_options(opt):
  opt.tool_options("compiler_cxx")

def configure(conf):
  root = os.path.dirname(root_path)
  if sys.platform.startswith("win"):
    conf.fatal("Bad luck - node.js does not support the native extensions on Windows yet.")
  conf.check_tool("compiler_cxx")
  conf.check_tool("node_addon")
  # Please use the OpenSSL version which was used for building Node.js
  conf.check(lib='crypto', libpath=['/usr/lib', '/usr/local/lib', '/opt/local/lib', '/usr/sfw/lib'], mandatory=True)
  if not conf.check(lib='gtbase', libpath=['/usr/lib', '/usr/local/lib', ("%s/%s/src/base/.libs" % (root, libgt))]):
    build_libgtbase(root)
    conf.check(lib='gtbase', libpath=['/usr/lib', '/usr/local/lib', ("%s/%s/src/base/.libs" % (root, libgt))], mandatory=True)

def build(bld):
  root = os.path.dirname(root_path)
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.cxxflags = ["-g", "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE", "-Wall"]
  obj.includes = "%s/%s/src/base" % (root, libgt)
  obj.lib = ["gtbase", "crypto"]
  obj.libpath = "%s/%s/src/base/.libs" % (root, libgt)
  obj.target = "timesignature"
  obj.source = "timesignature.cc"

def build_libgtbase(root):
  Utils.exec_command("cd %s/%s/ && CFLAGS=-fPIC ./configure --disable-shared && cd src/base && make && cd ../../.." % (root, libgt))

def test(ctx):
  status = Utils.exec_command('node tests.js')
  if status != 0:
    raise Utils.WafError('tests failed')

def shutdown():
  import Options
  if not Options.commands['distclean'] and not Options.commands['clean']:
    if os.path.exists('build/default/timesignature.node') and not os.path.exists('timesignature.node'):
      os.symlink('build/default/timesignature.node', 'timesignature.node')
    if os.path.exists('build/Release/timesignature.node') and not os.path.exists('timesignature.node'):
      os.symlink('build/Release/timesignature.node', 'timesignature.node')
  else:
    if os.path.lexists('timesignature.node'):
      os.unlink('timesignature.node')
    Utils.exec_command("cd %s/%s/ && make distclean && cd .." % (os.path.dirname(root_path), libgt))
