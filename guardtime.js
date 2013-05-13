var crypto = require('crypto'),
  http = require('http'),
  url = require('url'),
  fs = require('fs');

var timeSignature = require('bindings')('timesignature.node');
// support console.log(ts)
timeSignature.TimeSignature.prototype.inspect = function inspect() {
  return '<' + this.constructor.name + ' ' + JSON.stringify(this.verify(), null, '\t') + '>';
};
// conversion to primitive value, eg. when accessed in String context
timeSignature.TimeSignature.prototype.valueOf = function valueOf() {
  return this.getContent().toString();
};

var GuardTime = module.exports = {
  default_hashalg: 'SHA256',
  VER_RES : {
    PUBLIC_KEY_SIGNATURE_PRESENT : 1,
    PUBLICATION_REFERENCE_PRESENT : 2,
    DOCUMENT_HASH_CHECKED : 16,
    PUBLICATION_CHECKED : 32
  },
  TimeSignature: timeSignature.TimeSignature,
  publications: {
    data: '',
    last: '',
    updatedat: 0,
    lifetime: 60*60*7
  },
  service: {
    signer: url.parse('http://stamper.guardtime.net/gt-signingservice'),
    verifier: url.parse('http://verifier.guardtime.net/gt-extendingservice'),
    publications: url.parse('http://verify.guardtime.com/gt-controlpublications.bin')
  },

  conf: function (data) {
    if (data.signeruri)
      GuardTime.service.signer = url.parse(data.signeruri);
    if (data.verifieruri)
      GuardTime.service.verifier = url.parse(data.verifieruri);
    if (data.publicationsuri)
      GuardTime.service.publications = url.parse(data.publicationsuri);
    if (data.publicationsdata) {
      var d = GuardTime.TimeSignature.verifyPublications(data.publicationsdata); // exception on error
      GuardTime.publications.last = d;
      GuardTime.publications.data = data;
      GuardTime.publications.updatedat = Date.now();
    }
    if (data.publicationslifetime) {
      if (! isFinite(data.publicationslifetime) || data.publicationslifetime <= 0)
          throw new Error("Publications data lifetime must be a positive number.");
      GuardTime.publications.lifetime = data.publicationslifetime;
    }
  },

  sign: function (data, callback) {
    var hash;
    try {
      hash = crypto.createHash(GuardTime.default_hashalg);
      hash.update(data);
    } catch (err) {
      return callback(err);
    }
    GuardTime.signHash(hash.digest(), GuardTime.default_hashalg, callback);
  },

  signFile: function (filename, callback) {
    var hash, rs;
    try {
      hash = crypto.createHash(GuardTime.default_hashalg);
      rs = fs.createReadStream(filename, {'bufferSize': 128*1024});
      rs.on('data', function(chunk) { hash.update(chunk); });
      rs.on('error', function(err) {
        callback(err);
        rs.destroy();
      });
      rs.on('end', function() {
        GuardTime.signHash(hash.digest(), GuardTime.default_hashalg, callback);
      });
    } catch (err) {
      return callback(err);
    }
  },

  signHash: function (hash, alg) {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};
    var reqdata;
    try {
      reqdata = GuardTime.TimeSignature.composeRequest(hash, alg);
    } catch (err) {
      return callback(err);
    }
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
        } catch (err) {
          return callback(err);
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
    try {
      fs.writeFile(filename, ts.getContent(), 'binary', cb);
    } catch (err) {
      return cb(err);
    }
  },

  load: function (filename, cb) {
    fs.readFile(filename, function (err, data) {
      if (err) cb(err);
      try {
        var ts = new GuardTime.TimeSignature(data);
        cb(null, ts);
      } catch (err) { return cb(err); }
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
          GuardTime.publications.updatedat = Date.now();
        } catch (err) {
          return callback(err);
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

    var reqdata;
    try {
      reqdata = ts.composeExtendingRequest();
    } catch (err) {
      return callback(err);
    }
    GuardTime.service.verifier.method = 'POST';
    GuardTime.service.verifier.headers = {'Content-Length': reqdata.length};
    var req = http.request(GuardTime.service.verifier, function(res) {
      if (res.statusCode != 200) {
        return callback(new Error("Verification service error: " + res.statusCode +
            " (" + http.STATUS_CODES[res.statusCode] + ")"));
      }
      var extendingresponse = "";
      res.on('data', function (chunk) {
        extendingresponse += chunk.toString('binary');
      });
      res.on('end', function(){
        try{
          ts.extend(extendingresponse);
        } catch (err) {
          return callback(err);
        }
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
    try {
      var hash = crypto.createHash(ts.getHashAlgorithm());
      hash.update(data);
      GuardTime.verifyHash(hash.digest(), ts.getHashAlgorithm(), ts, callback);
    } catch (er) {
      return callback(er);
    }
  },

  verifyHash: function(hash, alg, ts) {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};
    var properties = {};
    // if publications file is not yet downloaded or data too old - download and recall itself
    if (!GuardTime.publications.data ||
          (GuardTime.publications.updatedat + GuardTime.publications.lifetime * 1000 < Date.now())) {
      return GuardTime.loadPublications(function(err){
        if (err)
          return callback(err);
        return GuardTime.verifyHash(hash, alg, ts, callback);
      });
    }
    try {
      properties = ts.verify();
      properties.verification_status |= ts.compareHash(hash, alg);
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
            properties = xts.verify();
            properties.verification_status |= xts.compareHash(hash, alg);
            properties.verification_status |= xts.checkPublication(GuardTime.publications.data);
          } catch (err) { return callback(err); }
          callback(null, properties.verification_status, properties);
        });
      }
      properties.verification_status |= ts.checkPublication(GuardTime.publications.data);
    } catch (err) {
      return callback(err);
    }
    callback(null, properties.verification_status, properties);
  },

  verifyFile: function(filename, ts) {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function')
      callback = function (){};
    try {
      var hash = crypto.createHash(ts.getHashAlgorithm());
      fs.createReadStream(filename, {'bufferSize': 128*1024})
        .on('data', function(chunk) { hash.update(chunk); })
        .on('error', function(er) {
          callback(er);
          rs.destroy();
        })
        .on('end', function() {
          GuardTime.verifyHash(hash.digest(), ts.getHashAlgorithm(), ts, callback);
      });
    } catch (err) {
      return callback(err);
    }
  }
};
