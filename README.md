note: this legacy project is not maintained any more.

---

# API to access Guardtime services.


Includes Guardtime C API in subdirectory libgt-x.y

How to build:

    npm install .
    npm link
or 

    node-gyp rebuild 


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

For API documentation please refer to
[node-guardtime-api.markdown](https://github.com/ristik/node-guardtime/blob/master/node-guardtime-api.markdown)

For more information about the Guardtime Keyless Signature service please have a look at
http://www.guardtime.com/signatures/technology-overview

As You are already here - this is the essence:
Guardtime service adds hash of your doc to a giant hash tree with globally unique
root value; and regularily publishes this root value in widely witnessed media.
This allows you to prove that your document did exist at certain point of time, you
used certain service endpoint, and this document was not modified ever after.

Needs Node.JS >= 0.8, <= 0.12; Windows is not tested.

[![build status](https://secure.travis-ci.org/ristik/node-guardtime.png)](http://travis-ci.org/ristik/node-guardtime)

---
Published under Apache license v. 2.0.
Copyright Guardtime AS 2014
