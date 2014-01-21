{
  'targets': [
    # libgtbase
    {
      'target_name': 'libgtbase',
      'type': 'static_library',
      'cflags': [
            # silence warnings
            '-Wno-sign-compare',
            '-Wno-pointer-sign',
      ],
      'sources': [
        'asn1_time_get.c',
        'asn1_time_get.h',
        'base32.c',
        'base32.h',
        'gt_asn1.c',
        'gt_asn1.h',
        'gt_base.c',
        'gt_base.h',
        'gt_crc32.c',
        'gt_crc32.h',
        'gt_datahash.c',
        'gt_fileio.c',
        'gt_info.c',
        'gt_internal.c',
        'gt_internal.h',
        'gt_publicationsfile.c',
        'gt_publicationsfile.h',
        'gt_timestamp.c',
        'gt_truststore.c',
        'hashchain.c',
        'hashchain.h'
      ],
      'variables': {
        # node v0.6.x doesn't give us its build variables,
        # but on Unix it was only possible to use the system OpenSSL library,
        # so default the variable to "true", v0.8.x node and up will overwrite it.
        'node_shared_openssl%': 'true',
      },
      'conditions': [
        ['OS=="mac"', {
          'xcode_settings': {
            'OTHER_CFLAGS': [
              # silence warnings
              '-Wno-sign-compare',
              '-Wno-pointer-sign',
              '-Wno-missing-field-initializers',
              '-mmacosx-version-min=10.5'
            ],
          }
        }],
        ['node_shared_openssl=="false"', {
          # so when "node_shared_openssl" is "false", then OpenSSL has been
          # bundled into the node executable. So we need to include the same
          # header files that were used when building node.
          'include_dirs': [
            '<(node_root_dir)/deps/openssl/openssl/include',
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
