var crypto = require('crypto'),
  util = require('util'),
  http = require('http'),
  url = require('url'),
  fs = require('fs');

var timeSignature = require('bindings')('timesignature.node');

 // workaround for bug in node 0.4.x
function url_parse(u) {
  var o = url.parse(u);
  if (o.path == null)
    o.path = o.pathname;
  return o;
}

var GuardTime = module.exports = {
  default_hashalg: 'SHA256',
  VER_ERR : {
    NO_FAILURES : 0,
    SYNTACTIC_CHECK_FAILURE : 1,
    HASHCHAIN_VERIFICATION_FAILURE : 2,
    PUBLIC_KEY_SIGNATURE_FAILURE : 16,
    NOT_VALID_PUBLIC_KEY_FAILURE : 64,
    WRONG_DOCUMENT_FAILURE : 128,
    NOT_VALID_PUBLICATION : 256
  },
  VER_RES : {
    PUBLIC_KEY_SIGNATURE_PRESENT : 1,
    PUBLICATION_REFERENCE_PRESENT : 2,
    DOCUMENT_HASH_CHECKED : 16,
    PUBLICATION_CHECKED : 32
  },
  TimeSignature: timeSignature.TimeSignature,
  publications: {
    data: '',
    last: ''
  },
  service: {
    signer: url_parse('http://stamper.guardtime.net/gt-signingservice'),
    verifier: url_parse('http://verifier.guardtime.net/gt-extendingservice'),
    publications: url_parse('http://verify.guardtime.com/gt-controlpublications.bin')
  },

  sign: function (data, callback) {
    var hash = crypto.createHash(GuardTime.default_hashalg);
    hash.update(data);
    GuardTime.signHash(hash.digest(), GuardTime.default_hashalg, callback);
  },

  signFile: function (filename, callback) {
    var hash = crypto.createHash(GuardTime.default_hashalg);
    var rs = fs.createReadStream(filename, {'bufferSize': 128*1024});
    rs.on('data', function(chunk) { hash.update(chunk); });
    rs.on('error', function(er) {
      callback(er);
      rs.destroy();
    });
    rs.on('end', function() {
      GuardTime.signHash(hash.digest(), GuardTime.default_hashalg, callback);
    });
  },

  signHash: function (hash, alg) {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};

    var reqdata = GuardTime.TimeSignature.composeRequest(hash, alg);
    GuardTime.service.signer.method = 'POST';
    GuardTime.service.signer.headers = {'Content-Length': reqdata.length};
    var req = http.request(GuardTime.service.signer, function(res) {
      if (res.statusCode != 200) {
        return callback(new Error("Signing service error: " + res.statusCode +
            " (" + http.STATUS_CODES[res.statusCode] + ")"));
      }
      var data = "";
      res.on('data', function (chunk) {
        data += chunk.toString('binary');
      });
      res.on('end', function(){
        try {
          ts = new GuardTime.TimeSignature(
            GuardTime.TimeSignature.processResponse(data));
        } catch (er) {
          return callback(er);
      }
      callback(null, ts);
      });
    });

    req.on('error', function(e) {
      return callback(new Error("Signing service error: " + e.message));
    });
    req.write(reqdata);
    req.end();
  },

  save: function (filename, ts, cb) {
    fs.writeFile(filename, ts.getContent(), 'binary', cb);
  },

  load: function (filename, cb) {
    fs.readFile(filename, function (err, data) {
      if (err) cb(err);
      try {
        var ts = new GuardTime.TimeSignature(data);
        cb(null, ts);
      } catch (err) {return cb(err);}
    });
  },

  loadSync: function (filename) {
    return new GuardTime.TimeSignature(fs.readFileSync(filename));
  },

  loadPublications: function () {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};
    var req = http.get(GuardTime.service.publications, function(res) {
      if (res.statusCode != 200) {
        return callback(new Error("Publications download: " + res.statusCode +
            " (" + http.STATUS_CODES[res.statusCode] + ")"));
      }
      var data = "";
      res.on('data', function (chunk) {
        data += chunk.toString('binary');
      });
      res.on('end', function(){
        try {
          var d = GuardTime.TimeSignature.verifyPublications(data); // exception on error
          GuardTime.publications.last = d;
          GuardTime.publications.data = data;
        } catch (er) {
          return callback(er);
        }
        callback(null);
      });
    });

    req.on('error', function(e) {
      return callback(new Error("Publications download: " + e.message));
    });
  },

  extend: function (ts) {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};

    var reqdata = ts.composeExtendingRequest();
    GuardTime.service.verifier.method = 'POST';
    GuardTime.service.verifier.headers = {'Content-Length': reqdata.length};
    var req = http.request(GuardTime.service.verifier, function(res) {
      if (res.statusCode != 200) {
        return callback(new Error("Verification service error: " + res.statusCode +
            " (" + http.STATUS_CODES[res.statusCode] + ")"));
      }
      var data = "";
      res.on('data', function (chunk) {
        data += chunk.toString('binary');
      });
      res.on('end', function(){
        var result = 0;
        try{
          result = ts.extend(data);
        } catch (er) {
          return callback(er);
        }
        if (callback)
          callback(null, ts);
      });
    });
    req.on('error', function(e) {
      return callback(new Error("Verification service error: " + e.message));
    });
    req.write(reqdata);
    req.end();
  },

  verify: function(data, ts) {
  var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};
    var hash = crypto.createHash(ts.getHashAlgorithm());
    hash.update(data);
    GuardTime.verifyHash(hash.digest(), ts.getHashAlgorithm(), ts, callback);
  },

  verifyHash: function(hash, alg, ts) {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};
    var result = 0;
    // if publications file is not yet downloaded - download and recall itself
    if (!GuardTime.publications.data) {
      return GuardTime.loadPublications(function(err){
        if (err)
          return callback(err);
        return GuardTime.verifyHash(hash, alg, ts, callback);
      });
    }
    try {
      result = ts.verify();
      result |= ts.compareHash(hash, alg);
      var is_new = ts.getRegisteredTime().getTime() > GuardTime.publications.last.getTime();
      if (!ts.isExtended() && !is_new) {
        return GuardTime.extend(ts, function(err, xts) {
          if (err) {
            //no failover:
            // return callback(err);
            //with failover:
            xts = ts;
          }
          try {
            result = xts.verify();
            result |= xts.compareHash(hash, alg);
            result |= xts.checkPublication(GuardTime.publications.data);
          } catch (err) { return callback(err); }
          callback(null, result);
        });
      }
      result |= ts.checkPublication(GuardTime.publications.data);
    } catch (err) {
      return callback(err);
    }
    callback(null, result);
  },

  verifyFile: function(filename, ts) {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};
    var hash = crypto.createHash(ts.getHashAlgorithm());
    var rs = fs.createReadStream(filename, {'bufferSize': 128*1024});
    rs.on('data', function(chunk) { hash.update(chunk); });
    rs.on('error', function(er) {
      callback(er);
      rs.destroy();
      // beware, no return!
    });
    rs.on('end', function() {
      GuardTime.verifyHash(hash.digest(), ts.getHashAlgorithm(), ts, callback);
    });
  }
}

