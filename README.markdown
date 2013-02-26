# API to access GuardTime services.


Includes GuardTime C API in subdirectory libgt-x.y

How to build:
    npm link
or 
    node-waf configure build test install


Hello world:

    var gt = require('guardtime');

    gt.sign('Hello world!', function(err, ts) {
      if (err)
        throw err;
      gt.verify('Hello world!', ts, function(err, checkflags, props){
        if (err) 
          throw err;
        console.log('All ok; signed by ' + props.location_name + ' at ' + props.registered_time);
      });
    });

For API documentation please see file (/node-guardtime-api.markdown)

For more information about GuardTime Keyless Signature service please go to
http://www.guardtime.com/signatures/technology-overview

As You are already here - this is the essence:
GuardTime service adds hash of your doc to a giant hash tree with globally unique
root value; and regularily publishes this root value in widely witnessed media.
This allows you to prove that your document did exist at certain point of time, you
used certain service endpoint, and this document was not modified ever after.

Needs Node.JS >= 0.4.0; Windows is not supported.

[![build status](https://secure.travis-ci.org/ristik/node-guardtime.png)](http://travis-ci.org/ristik/node-guardtime)

---
Published under Apache license v. 2.0.
Copyright GuardTime AS 2010-2013
