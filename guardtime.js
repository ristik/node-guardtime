var crypto = require('crypto');
var sys = require('sys');
var http = require('http');
var fs = require('fs');
var TimeSignature = require('./timesignature').TimeSignature;


function parseUri(sourceUri){
    var uriPartNames = ["source","protocol","authority","domain","port","path","directoryPath","fileName","query","anchor"];
    var uriParts = new RegExp("^(?:([^:/?#.]+):)?(?://)?(([^:/?#]*)(?::(\\d*))?)?((/(?:[^?#](?![^?#/]*\\.[^?#/.]+(?:[\\?#]|$)))*/?)?([^?#/]*))?(?:\\?([^#]*))?(?:#(.*))?").exec(sourceUri);
    var uri = {};
    
    for(var i = 0; i < 10; i++){
        uri[uriPartNames[i]] = (uriParts[i] ? uriParts[i] : "");
    }
    if(uri.directoryPath.length > 0){
        uri.directoryPath = uri.directoryPath.replace(/\/?$/, "/");
    }    
    return uri;
}


var GuardTime = module.exports = {
  default_hashalg: 'sha256',
  res: {  // verification result bitmap constants
  	PUBLIC_KEY_SIGNATURE_PRESENT: 1,
  	PUBLICATION_REFERENCE_PRESENT: 2,
  	DOCUMENT_HASH_CHECKED: 16,
  	PUBLICATION_CHECKED: 32
  },
  publications: {
  	data: '',
  	last: ''
  },
  service: {
    signer: parseUri('http://stamper.guardtime.net/gt-signingservice'),
    verifier: parseUri('http://verifier.guardtime.net/gt-extendingservice'),
    publications: parseUri('http://verify.guardtime.com/gt-controlpublications.bin')
  },
  
  sign: function (data, callback) {
    var hash = crypto.createHash(GuardTime.default_hashalg);
    hash.update(data);
    GuardTime.signHash(new Buffer(hash.digest(), encoding='binary'), 
    			GuardTime.default_hashalg, callback);    		
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
  	      GuardTime.signHash(new Buffer(hash.digest(), encoding='binary'), 
    				GuardTime.default_hashalg, callback);  
  	});
  },
  
  signHash: function (hash, alg) {  // hash must be binary Buffer!
  	var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function') 
    	callback = function (){};

    var sserver = http.createClient(
         GuardTime.service.signer.port == ''? 80 : GuardTime.service.signer.port, GuardTime.service.signer.domain);
	var reqdata = TimeSignature.composeRequest(hash, alg);
    var request = sserver.request('POST', GuardTime.service.signer.path, 
        {'host': GuardTime.service.signer.domain, 
         'Content-Length': reqdata.length});
	request.write(reqdata);
	request.end();

	request.on('response', function (response) {
    	//console.log('STATUS: ' + response.statusCode);
    	var resp = new Buffer(5500), pos = 0;  // todo: detect overflow
    	response.on('data', function(chunk){
    	   resp.write(chunk.toString('binary'), pos, encoding='binary');
    	   pos = pos + chunk.length;
         }).on('end', function(){
           try{
             ts = new TimeSignature(TimeSignature.processResponse(resp.slice(0, pos)));
           } catch (er) {
        	 return callback(er);
           }
           callback(null, ts);
        });
      });  
  },
  
  save: function (filename, ts, cb) {
  	 fs.writeFile(filename, ts.getContent(), 'binary', cb);
  },
  
  load: function (filename, cb) {
	 fs.readFile(filename, function (err, data) {
  	 	if (err) cb(err);
  	 	try {
  			var ts = new TimeSignature(data);
	  		cb(null, ts);
  		} catch (err) {return cb(err);}
	 });  
  },
  
  loadSync: function (filename) {
	 return new TimeSignature(fs.readFileSync(filename));
  },
  
  loadPublications: function () {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function') 
    	callback = function (){};
    
    var sserver = http.createClient(
         GuardTime.service.publications.port == ''? 80 : GuardTime.service.publications.port, GuardTime.service.publications.domain);
    var request = sserver.request('GET', GuardTime.service.publications.path, 
        {'host': GuardTime.service.publications.domain});
    request.end();
    request.on('response', function (response) {
    	var resp = new Buffer(6000), pos = 0;  // todo: detect overflow
    	response.on('data', function(chunk){
    	   resp.write(chunk.toString('binary'), pos, encoding='binary');
    	   pos = pos + chunk.length;
         }).on('end', function(){
           var pub = resp.slice(0, pos);
           try {
             var d = TimeSignature.verifyPublications(pub); // exception on error
             GuardTime.publications.last = d;
           	 GuardTime.publications.data = pub;
           	} catch (er) {
           		return callback(er);
           	}
           	callback(null);
        });
      });
  },
  
  extend: function (ts) {
    var callback = arguments[arguments.length - 1];
    if (typeof(callback) !== 'function') 
    	callback = function (){};
    	
    var sserver = http.createClient(
         GuardTime.service.verifier.port == ''? 80 : GuardTime.service.verifier.port, GuardTime.service.verifier.domain);
	var reqdata = ts.composeExtendingRequest();
    var request = sserver.request('POST', GuardTime.service.verifier.path, 
        {'host': GuardTime.service.verifier.domain, 
         'Content-Length': reqdata.length});
	request.write(reqdata);
	request.end();
	
	request.on('response', function (response) {
    	// console.log('STATUS: ' + response.statusCode);
    	var resp = new Buffer(3500), pos = 0;  // todo: detect overflow
    	response.on('data', function(chunk){
    	   resp.write(chunk.toString('binary'), pos, encoding='binary');
    	   pos = pos + chunk.length;
         }).on('end', function(){
           var result = 0;
           try{
             result = ts.extend(resp.slice(0, pos));
           } catch (er) {
           	 return callback(er);
           }
           if (callback) 
           	   callback(result, ts);
        });
      });
   },
   
  verify: function(data, ts) {
		var callback = arguments[arguments.length - 1];
		if (typeof(callback) !== 'function') 
				callback = function (){}; 
		var hash = crypto.createHash(ts.getHashAlgorithm());
		hash.update(data);
		GuardTime.verifyHash(new Buffer(hash.digest(), encoding='binary'), ts.getHashAlgorithm(),
					ts, callback);   	
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
					    // no failover:
						// return callback(err);
						// failover:
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
			
		} catch (err) { return callback(err); }
		
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
			  GuardTime.verifyHash(new Buffer(hash.digest(), encoding='binary'), 
						ts.getHashAlgorithm(), ts, callback);  
		});   
   }

    
}
  	
