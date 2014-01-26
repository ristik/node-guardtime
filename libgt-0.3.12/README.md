# Bundled Guardtime C API

This is a stripped version of Guardtime C API. Full tarball is available at http://download.guardtime.com/libgt-0.3.12.tar.gz

Changes:

  - Makefiles, documentation, http transport and png format integration are removed (`/src/base` and `/test` are left);
  - gyp makefile `src/base/base.gyp` is added.

It is possible to use pre-installed Guardtime C API:

 - if detected by pkg-conf
 - if specified explicitly using npm or gyp parameter --libgt=/location/of/libgt (libraries must be under lib and headers under include). Example: `npm install --libgt=/usr/local`.

Otherwise, this version will be compiled and linked into produced node add-on.

Note that this version uses Mozilla trusted root certificate list which is distributed with node.js source. Pre-installed GT C API may use something else: .PEM bundle under /etc/pki/... or Mac OS X native OpenSSL which is patched to use Keychain (and later deprecated).
