// informal unit-tests to test GuardTime node.js API.
// expectations:
//   computer's wall clock drift < 5 minutes;
//   > 40 days old, non-extended signature file (TestData.txt.gtts1)
//   signed file (TestData.txt)
//   internet connectivity
//   GW with public identity must be used.
//   run in module build directory

var testsigfile  = __dirname + '/../libgt-0.3.11/test/TestData.txt.gtts1',
    testdatafile = __dirname + '/../libgt-0.3.11/test/TestData.txt';

var gt = require('../guardtime'), 
    TimeSignature = gt.TimeSignature,
    crypto = require('crypto');

module.exports = {
  test_publications_download: function (test) {
    test.expect(3);
    gt.loadPublications(function (err) {
      test.ok(err === null, err);
      var lastpubdate = TimeSignature.verifyPublications(gt.publications.data);
      var now = new Date();
      test.ok(lastpubdate.getTime() < now.getTime(), "last publication must be older than wall clock time");
      test.ok(lastpubdate.getTime() + 1000*60*60*24*40 > now.getTime(), "last publication must be no older than 40 days");
      test.done();
    });
  },
  sig: '',  // shared state, used below
  test_string_signing: function (test) {
    test.expect(2);
    gt.sign('Hello!', function (err, ts) {
      test.ok(err === null, err);
      test.ok(ts instanceof TimeSignature, 'signing did not return an instance of TimeSignature');
      sig = ts;
      test.done();
    });
  },
  test_string_verification_immediately: function (test) {
    test.expect(3);
    gt.verify('Hello!', sig, function(err, res, props){
      test.ok(err === null, err);
      test.equal(res, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT +
            gt.VER_RES.DOCUMENT_HASH_CHECKED + 
            gt.VER_RES.PUBLICATION_CHECKED);
      test.ok(props.verification_status == res);
      test.done();
    });
  },
  test_signature_properties: function (test) {
    test.expect(3);
    var now = new Date();
    var tsdate = sig.getRegisteredTime();
    test.ok(tsdate.getTime() + 1000*60*10 > now.getTime(), 
          "signing time is not within 5 minutes (check your wall clock?)");
    test.ok(tsdate.getTime() - 1000*60*10 < now.getTime(), 
          "signing time is not within 5 minutes (check your wall clock?)");
    test.ok(sig.getSignerName().match(/^GT :/));
    test.done();
  },
  test_verifying_tampered_data: function (test) {
    test.expect(3);
    gt.verify('UnHello!', sig, function (err, res, properties) {
      test.ok(err.message.match(/different document/));
      test.ok(res === undefined); 
      test.ok(properties === undefined);
      test.done();
    });
  },
  test_loadSync_corrupted_token: function (test) {
    test.expect(1);
    test.throws(function () {
      var invalid = gt.loadSync(testdatafile);
      }, /Invalid format/i
    );
    test.done();
  },
  test_load_corrupted_token: function (test) {
    test.expect(3);
    gt.load(testdatafile, function (err, ts) {
      test.ok(err !== null);
      test.ok(err.message.match(/Invalid format/i));
      test.ok(ts === undefined);
      test.done();
    });
  },
  old: '', // shared 'old' token 
  test_more_token_methods: function (test) {
    test.expect(7);
    test.ok(!sig.isExtended());
    test.equal(sig.getHashAlgorithm().toUpperCase(), gt.default_hashalg.toUpperCase());
    old = gt.loadSync(testsigfile);
    test.ok(! old.isExtended(), "please make sure that testdata is not extended");
    test.equal(old.verify().verification_status, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT);
    test.ok(old.isEarlierThan(sig));
    test.ok(!sig.isEarlierThan(old));
    test.ok(old.getSignerName() !== null);  // blank if not present
    test.done();
  },
  test_extending_token: function (test) {
    test.expect(5);
    gt.extend(old, function (err, xold) {
      test.ok(err === null, err);
      test.ok(xold.isExtended());
      test.equal(xold.verify() | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT, 
              gt.VER_RES.PUBLICATION_REFERENCE_PRESENT);
      gt.verifyFile(testdatafile, xold, function (err, res) {
        test.ok(err === null, err);
        test.equal(res | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT, 
                gt.VER_RES.DOCUMENT_HASH_CHECKED + 
                gt.VER_RES.PUBLICATION_CHECKED + gt.VER_RES.PUBLICATION_REFERENCE_PRESENT);
        test.done();
      });
    });
  },
  test_verifying_old_stuff: function (test) {
    test.expect(3);
    gt.load(testsigfile, function (err, ts) {
      test.ok(err === null, err);
      gt.verifyFile(testdatafile, ts, function (err, res) {
        test.ok(err === null, err);
        test.equal(res | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT, 
              gt.VER_RES.DOCUMENT_HASH_CHECKED + 
              gt.VER_RES.PUBLICATION_CHECKED + gt.VER_RES.PUBLICATION_REFERENCE_PRESENT);
        test.done();
      });
    });
  },
  test_file_verify: function (test) {
    test.expect(3);
    gt.load(testsigfile, function (err, ts) {
      test.ok(err === null, err);
      gt.verifyFile(testdatafile, ts, function(err, res) {
        test.ok(err === null, err);
        test.equal(res | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT, 
              gt.VER_RES.DOCUMENT_HASH_CHECKED + 
              gt.VER_RES.PUBLICATION_CHECKED + gt.VER_RES.PUBLICATION_REFERENCE_PRESENT);
        test.done();
      });
    });
  },
  test_external_hashing_sha512: function (test) {
    test.expect(3);
    var h = crypto.createHash('sha512');
    h.update('Hi there!');
    var hd = h.digest();
    gt.signHash(hd, 'sha512', function (e, ts) {
      test.ok(e === null, e);
      test.ok(ts instanceof TimeSignature, 'signing did not return an instance of TimeSignature');
      test.equal(ts.verify().verification_status, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT);
      test.done();
    });
  },
  test_external_hashing_sha1_buffer: function (test) {
    test.expect(4);
    var h = crypto.createHash('sha1');
    h.update('Hi there again');
    var hd = h.digest();
    gt.signHash(new Buffer(hd, encoding='binary'), 'sha1', function(e, ts) {
      test.ok(e === null, e);
      test.ok(ts != undefined);
      test.ok(ts instanceof TimeSignature, 'signing did not return an instance of TimeSignature');
      test.equal(ts.verify().verification_status, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT);
      test.done();
    });
  }
};


