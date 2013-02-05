{
  'targets': [
    # timesignature
    {
      'target_name': 'timesignature',
      'include_dirs': [
        'libgt-0.3.10/src/base'
      ],
      'sources': [
        'timesignature.cc',
      ],
      'dependencies': [
        'libgt-0.3.10/src/base/base.gyp:libgtbase',
        'libgt-0.3.10/src/http/http.gyp:libgthttp',
        'libgt-0.3.10/src/png/png.gyp:libgtpng',
      ],
      'link_settings': {
        'libraries': [
          '-lcrypto',
          '-lcurl'
        ],
        # Ensure the library path is recorded into the module to be able
        # find the shared libraries without specifying LD_LIBRARY_PATH
        'ldflags': [
          '-Rbuild/Release',
          '-Rbuild/default',
          '-Rbuild/Debug'
        ],
      },
      'variables': {
        # node v0.6.x doesn't give us its build variables,
        # but on Unix it was only possible to use the system OpenSSL library,
        # so default the variable to "true", v0.8.x node and up will overwrite it.
        'node_shared_openssl%': 'true',
      },
      'conditions': [
        ['node_shared_openssl=="false"', {
          # so when "node_shared_openssl" is "false", then OpenSSL has been
          # bundled into the node executable. So we need to include the same
          # header files that were used when building node.
          'include_dirs': [
            '<(node_root_dir)/deps/openssl/openssl/include'
          ],
          "conditions" : [
            ["target_arch=='ia32'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/piii" ]
            }],
            ["target_arch=='x64'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/k8" ]
            }],
            ["target_arch=='arm'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/arm" ]
            }],
          ]
        }]
      ],
    },
  ],
}
