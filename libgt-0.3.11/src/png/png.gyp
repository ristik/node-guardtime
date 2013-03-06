{
  'targets': [
   # png
    {
      'target_name': 'png',
      'include_dirs': [
        '../base',
        '../http'
      ],
      'sources': [
        'png_insert.c',
        'png_create.c',
        'png_extend.c',
        'png_verify.c'
      ],
      'dependencies': [
        'libgtpng',
        '../base//base.gyp:libgtbase',
        '../http/http.gyp:libgthttp',
      ],
    },
    # libgtpng
    {
      'target_name': 'libgtpng',
      'type': 'static_library',
      'include_dirs': [
        '../base',
        '../http'
      ],
      'sources': [
        'gt_png.c',
        'gt_png.h',
        'gtpng_crc32.c',
        'gtpng_crc32.h'
      ],
      'direct_dependent_settings': {
        'defines': [
        ],
        'linkflags': [
        ],
        'cflags': [
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
