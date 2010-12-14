var gt = require('./guardtime');

ts1 = gt.loadSync('test.js.gtts');
ts2 = gt.loadSync('/Users/risto/cat.gif.ts');

/*
gt.loadPublications(function() {
	gt.extend(ts1, function(err, extended_ts){
						if (err) 
							console.error(err);
						console.log(extended_ts);
					});
	gt.extend(ts2, function(err, extended_ts){
						if (err) 
							console.error(err);
						console.log(extended_ts);
					});

	console.log('got pubs');
});

 */

gt.verify('Hello!', ts1, function(err, result) {
	if (err)
		return console.error(err);
	console.log("ver result: " + result);
});


console.log("isearlier: " + ts1.isEarlierThan(ts2));
console.log("isearlier: " + ts2.isEarlierThan(ts1));
console.log("isearlier: " + ts1.isEarlierThan(ts1));

gt.sign('Hello!', function(err, ts) {
  if(err) {
    return console.error(err);
  } else {
    console.log('sign' + ts.verify());
    gt.extend(ts, function(err, ts) {
          console.log("ext result: " + err + ts)
    });
    console.log('isextended ' + ts.isExtended());    
    gt.verify('Hello!', ts, function(err, res){
    	console.log('ver' + err, res);});
    gt.save('test2.gtts', ts);
  }
});
gt.signFile('test.js', function(err, ts) {
  if(err) {
    return console.error(err);
  } else {
    console.log('signFile: ' + ts.verify());
    gt.save('test.js.gtts', ts);
  }
});


