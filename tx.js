var gt = require('./guardtime');

gt.conf({
    signeruri:       'http://stamper.us.guardtime.net/gt-signingservice',
    verifieruri:     'http://192.168.33.131/longer',
    publicationsuri: 'http://verify.guardtime.com/gt-controlpublications.bin',
    verifierthreads: 1}
);

var testsigfile  = './libgt-0.3.12/test/TestData.txt.gtts1',
    testdatafile = './libgt-0.3.12/test/TestData.txt';


gt.loadPublications(function(err){
  if (err) throw err;
  console.log("got pub");
});

var old = gt.loadSync(testsigfile);

gt.verifyFile(testdatafile, old, function (err, flag, res) {
  gt.extend(old, function(err, res){
    if (err)
      console.error(err);
    gt.conf({ verifieruri: 'http://192.168.33.131/loop'});
    gt.extend(old, function(err, res){
      if (err)
        console.error(err);
    });
  });
});
