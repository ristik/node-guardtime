// informal unit-tests of GuardTime node.js API.
// expectations:
//   computer's wall clock drift < 5 minutes;
//   > 40 days old, non-extended signature file (TestData.txt.gtts1)
//   signed file (TestData.txt)
//   internet connectivity
//   GW with public identity must be used.
//   run in module build directory

var testsigfile  = __dirname + '/../libgt-0.3.12/test/TestData.txt.gtts1',
    testdatafile = __dirname + '/../libgt-0.3.12/test/TestData.txt';

var gt = require('../guardtime'),
    TimeSignature = gt.TimeSignature,
    crypto = require('crypto'),
    assert = require('assert');


describe('GuardTime', function(){
  this.timeout(6000); // note that signing takes usually 1..2 seconds, thus increase limit

  var newconf = {
    signeruri:       'http://stamper.us.guardtime.net/gt-signingservice',
    verifieruri:     'http://verifier.us.guardtime.net/gt-extendingservice',
    publicationsuri: 'http://verify.guardtime.com/gt-controlpublications.bin',
    signerthreads:       4,
    verifierthreads:     1, // changed
    publicationsthreads: 1,
    publicationsdata: '',
    publicationslifetime: 60*60*7
  };

  var sig = ''; // shared fresh signature token
  var old = ''; // shared old signature token, loaded from file

  describe('loadPublications()', function(){
    it('downloads publications data for verification', function(done){
      gt.loadPublications( function (err, ts) {
        assert.ifError(err);
        var lastpubdate = TimeSignature.verifyPublications(gt.publications.data);
        var now = new Date();
        assert.ok(lastpubdate.getTime() < now.getTime(), "last publication must be older than wall clock time");
        assert.ok(lastpubdate.getTime() + 1000*60*60*24*40 > now.getTime(), "last publication must be no older than 40 days");
        done();
      });
    });
  });

  describe('sign()', function(){
    it('signs a text string', function(done){
      gt.sign('Hello!', function (err, ts) {
        assert.ifError(err);
        assert.ok(ts instanceof TimeSignature, 'signing did not return an instance of TimeSignature');
        sig = ts;
        done();
      });
    });
  });

  describe('verify()', function(){
    it('verifies the signature on freshly signed text string', function(done){
      gt.verify('Hello!', sig, function(err, res, props){
        assert.ifError(err);
        assert.equal(res, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT +
              gt.VER_RES.DOCUMENT_HASH_CHECKED +
              gt.VER_RES.PUBLICATION_CHECKED);
        assert.ok(props.verification_status == res);
        done();
      });
    });
  });

  describe('TimeSignature.getRegisteredTime()', function(){
    it("checks if fresh signature token's signing time is reasonable", function(done){
      var now = new Date();
      var tsdate = sig.getRegisteredTime();
      assert.ok(tsdate.getTime() + 1000*60*10 > now.getTime(),
            "signing time is not within 5 minutes (check your wall clock?)");
      assert.ok(tsdate.getTime() - 1000*60*10 < now.getTime(),
            "signing time is not within 5 minutes (check your wall clock?)");
      done();
    });
  });

  describe('TimeSignature.getSignerName()', function(){
    it("checks if signer ID namespace starts with GT", function(done){
      assert.ok(sig.getSignerName().match(/^GT :/));
      done();
    });
  });

  describe('verify()', function(){
    it('checks if data tampering is detected', function(done){
      gt.verify('NotHello!', sig, function (err, res, properties) {
        assert.ok(err.message.match(/different document/), "unexpected error message");
        assert.ok(res === undefined);
        assert.ok(properties === undefined);
        done();
      });
    });
  });

  describe('loadSync()', function(){
    it('tests loading of corrupted token', function(done){
      assert.throws(function () {
        var invalid = gt.loadSync(testdatafile);
        }, /Invalid format/i
      );
      done();
    });
  });

  describe('load()', function(){
    it('tests loading of corrupted token', function(done){
      gt.load(testdatafile, function (err, ts) {
        assert.ok(err !== null);
        assert.ok(err.message.match(/Invalid format/i));
        assert.ok(ts === undefined);
        done();
      });
    });
  });

  describe('TimeSignature.blaah()', function(){
    it('tests some other TimeSignature accessors', function(done){
      assert.ok(!sig.isExtended());
      assert.equal(sig.getHashAlgorithm().toUpperCase(), gt.default_hashalg.toUpperCase());
      old = gt.loadSync(testsigfile);
      assert.ok(! old.isExtended(), "please make sure that testdata is not extended");
      assert.equal(old.verify().verification_status, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT);
      assert.ok(old.isEarlierThan(sig));
      assert.ok(!sig.isEarlierThan(old));
      assert.ok(old.getSignerName() !== null);  // blank if not present
      done();
    });
  });

  describe('extend() and verify()', function(){
    it('extends a old signature token, and then verifies it', function(done){
      gt.extend(old, function (err, xold) {
        assert.ifError(err);
        assert.ok(xold.isExtended());
        assert.equal(xold.verify() | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT,
                gt.VER_RES.PUBLICATION_REFERENCE_PRESENT);
        gt.verifyFile(testdatafile, xold, function (err, res) {
          assert.ifError(err);
          assert.equal(res | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT,
                  gt.VER_RES.DOCUMENT_HASH_CHECKED +
                  gt.VER_RES.PUBLICATION_CHECKED + gt.VER_RES.PUBLICATION_REFERENCE_PRESENT,
                  "unexpected verification result code");
          done();
        });
      });
    });
  });

  describe('verify()', function(){
    it('verifies old signature token, this includes automatic extending', function(done){
      gt.load(testsigfile, function (err, ts) {
        assert.ifError(err);
        gt.verifyFile(testdatafile, ts, function (err, res) {
          assert.ifError(err);
          assert.equal(res | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT,
                gt.VER_RES.DOCUMENT_HASH_CHECKED +
                gt.VER_RES.PUBLICATION_CHECKED + gt.VER_RES.PUBLICATION_REFERENCE_PRESENT,
                "unexpected verification result code");
          done();
        });
      });
    });
  });

  describe('conf()', function(){
    it('changes service configuration', function(done){
      gt.conf(newconf);
      assert.equal(gt.service.signer.method, 'POST');
      assert.equal(gt.service.verifier.agent.maxSockets, newconf.verifierthreads);
      done();
    });
  });

  describe('verifyFile() etc', function(){
    it('test_verifying_old_stuff_with_pub_dl', function(done){
      gt.publications.updatedat = 0;
      gt.load(testsigfile, function (err, ts) {
        assert.ifError(err);
        // two async verifications after pub. file download
        var cntr = 0;
        gt.verifyFile(testdatafile, ts, function (err, res) {
          assert.ifError(err);
          if (++cntr == 2)
            done();
        });
        gt.verifyFile(testdatafile, ts, function (err, res) {
          assert.ifError(err);
          assert.ok(gt.publications.updatedat > 0, 'oops, publications not refreshed');
          assert.equal(res | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT,
                gt.VER_RES.DOCUMENT_HASH_CHECKED +
                gt.VER_RES.PUBLICATION_CHECKED + gt.VER_RES.PUBLICATION_REFERENCE_PRESENT);
          if (++cntr == 2)
            done();
        });
      });
    });
  });

  describe('verifyFile()', function(){
    it('test_file_verify', function(done){
      gt.load(testsigfile, function (err, ts) {
        assert.ifError(err);
        gt.verifyFile(testdatafile, ts, function(err, res) {
          assert.ok(err === null, err);
          assert.equal(res | gt.VER_RES.PUBLICATION_REFERENCE_PRESENT,
                gt.VER_RES.DOCUMENT_HASH_CHECKED +
                gt.VER_RES.PUBLICATION_CHECKED + gt.VER_RES.PUBLICATION_REFERENCE_PRESENT);
          done();
        });
      });
    });
  });

  describe('signHash()', function(){
    it('signs a externally produced sha512 digest', function(done){
      var h = crypto.createHash('sha512');
      h.update('Hi there!');
      var hd = h.digest();
      gt.signHash(hd, 'sha512', function (err, ts) {
        assert.ifError(err);
        assert.ok(ts instanceof TimeSignature, 'signing did not return an instance of TimeSignature');
        assert.equal(ts.verify().verification_status, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT);
        done();
      });
    });
  });

  describe('signHash()', function(){
    it('signs a Buffer with sha1 hash', function(done){
      var h = crypto.createHash('sha1');
      h.update('Hi there again');
      var hd = h.digest();
      gt.signHash(new Buffer(hd, 'binary'), 'sha1', function(err, ts) {
        assert.ifError(err);
        assert.ok(ts !== undefined);
        assert.ok(ts instanceof TimeSignature, 'signing did not return an instance of TimeSignature');
        assert.equal(ts.verify().verification_status, gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT);
        done();
      });
    });
  });
});
