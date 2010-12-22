var gt = require('./guardtime');


gt.sign('Hello!', function(err, ts) {
  if(err) {
    return console.error(err);
  } else {
    gt.verify('Hello!', ts, function(err, res){
    	console.log("Error: " + err + "; Flags: " + res + "; Time: " + ts.getRegisteredTime());});
  }
});


var ts2 = gt.loadSync('/Users/risto/cat.gif.ts');
gt.verifyFile('/Users/risto/cat.gif', ts2, function(err, res){
    	console.log("Error: " + err + 
    				"; Flags: " + res + 
    				"; Time: " + ts2.getRegisteredTime());});
