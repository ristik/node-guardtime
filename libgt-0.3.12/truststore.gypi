{  # gyp mangles variables ending with _file, _dir
  'variables': {
    'glob': '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].0'
  },
  'conditions': [
    [ '"ok" == "<!(\[ -f /etc/ssl/certs/ca-certificates.crt \] && echo ok || true)"',
    {'variables': {'ca_f': '/etc/ssl/certs/ca-certificates.crt'}},
    {
    'conditions': [ [ '"ok" == "<!(\[ -f /etc/pki/tls/certs/ca-bundle.trust.crt \] && echo ok || true)"',
      {'variables': {'ca_f': '/etc/pki/tls/certs/ca-bundle.trust.crt'}},
      {
      'conditions': [ [ '"ok" == "<!(\[ -f /usr/share/ssl/certs/ca-bundle.trust.crt \] && echo ok || true)"',
        {'variables': {'ca_f': '/usr/share/ssl/certs/ca-bundle.trust.crt'}},
        {
        'conditions': [ [ '"ok" == "<!(\[ -f /usr/local/share/certs/ca-root.trust.crt \] && echo ok || true)"',
          {'variables': {'ca_f': '/usr/local/share/certs/ca-root.trust.crt'}},
          {
          'conditions': [ [ '"ok" == "<!(\[ -f /etc/ssl/cert.pem \] && echo ok || true)"',
            {'variables': {'ca_f': '/etc/ssl/cert.pem'}},
            {'variables': {'ca_f': ''}
            } ] ]
          } ] ]
        } ] ]
      } ] ]
    }
    ],
    [ '"" != "<!(find /etc/ssl/certs -maxdepth 1 -name \'<(glob)\' -print -quit 2>/dev/null || true)"',
    {'variables': {'ca_d': '/etc/ssl/certs'}},
    {
      'conditions': [ [ '"" != "<!(find /opt/local/etc/openssl/certs/ -maxdepth 1 -name \'<(glob)\' -print -quit 2>/dev/null || true)"',
      {'variables': {'ca_d': '/opt/local/etc/openssl/certs'}},
      {'variables': {'ca_d': ''}}
      ]]
    } ]
  ]
}
