// informal unit-tests to test GuardTime node.js API.
// expectations:
//   computer's wall clock drift < 5 minutes;
//   > 40 days old, non-extended signature file cat.gif.gtts
//   signed file cat.gif
//   internet connectivity
//   GW with public identity is used.
//   run in module build directory

var gt = require('./guardtime'), 
  TimeSignature = gt.TimeSignature,
  assert = require('assert');

gt.loadPublications(function(err) {
    assert.ok(err == null, err);
    var lastpubdate = TimeSignature.verifyPublications(gt.publications.data);
	var now = new Date();
	assert.ok(lastpubdate.getTime() < now.getTime(), "last publication must be older than wall clock");
	assert.ok(lastpubdate.getTime() + 1000*60*60*24*40 > now.getTime(), "last publication must be no older than 40 days");

	gt.sign('Hello!', function(err, ts) {
	  assert.ok(err == null, err);
	  gt.verify('Hello!', ts, function(err, res){
		assert.ok(err == null, err);
		assert.equal(res, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT +
				gt.VER_RES.DOCUMENT_HASH_CHECKED + 
				gt.VER_RES.PUBLICATION_CHECKED);
	  });
	  var tsdate = ts.getRegisteredTime();
	  assert.ok(tsdate.getTime() + 1000*60*10 > now.getTime(), "signing time is not within 5 minutes (check your wall clock?)");
	  assert.ok(tsdate.getTime() - 1000*60*10 < now.getTime(), "signing time is not within 5 minutes (check your wall clock?)");
	  
	  assert.ok(ts.getSignerName().match(/public/));
	  
	  gt.verify('UnHello!', ts, function(err, res) {
		assert.ok(err.message.match(/different document/));
		assert.ok(res == null); 
	  });
	  
	  assert.throws(function(){
  	  		var invalid = gt.loadSync('cat.gif');
  	  	}, /Invalid format/i
  	  );
	  gt.load('cat.gif', function(err, ts) {
	  	assert.ok(err.message.match(/Invalid format/i));
	  	assert.ok(ts == null);
	  });
	  
	  assert.ok(!ts.isExtended());
	  assert.equal(ts.getHashAlgorithm().toUpperCase(), gt.default_hashalg.toUpperCase());
	  var old = gt.loadSync('cat.gif.gtts');
	  assert.ok(! old.isExtended(), "please make sure that testdata is not extended");
	  assert.equal(old.verify(), gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT);
	  assert.ok(old.isEarlierThan(ts));
	  assert.ok(!ts.isEarlierThan(old));
  	  assert.ok(old.getSignerName() != null);  // blank if not present

	  if (!old.isExtended()) {
		gt.extend(old, function(err, xold) {
		  assert.ok(err == null, err);
	      assert.equal(xold.verify(), 0);
		  assert.ok(xold.isExtended());
		  gt.verifyFile('cat.gif', xold, function(err, res) {
			assert.ok(err == null, err);
			assert.equal(res, gt.VER_RES.DOCUMENT_HASH_CHECKED + 
					gt.VER_RES.PUBLICATION_CHECKED); 
		  });
		});
	  }
	  gt.load('cat.gif.gtts', function(err, ts) {
	    gt.verifyFile('cat.gif', ts, function(err, res) {
		  assert.ok(err == null, err);
		  assert.equal(res, gt.VER_RES.DOCUMENT_HASH_CHECKED + 
		  			gt.VER_RES.PUBLICATION_CHECKED);
	    });
	  });
	 
	});
});

