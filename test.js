function dump(arr,level) {
	var dumped_text = "";
	if(!level) level = 0;
	
	//The padding given at the beginning of the line.
	var level_padding = "";
	for(var j=0;j<level+1;j++) level_padding += "    ";
	
	if(typeof(arr) == 'object') { //Array/Hashes/Objects 
		for(var item in arr) {
			var value = arr[item];
			
			if(typeof(value) == 'object') { //If it is an array,
				dumped_text += level_padding + "'" + item + "' ...\n";
				dumped_text += dump(value,level+1);
			} else {
				dumped_text += level_padding + "'" + item + "' => \"" + value + "\"\n";
			}
		}
	} else { //Stings/Chars/Numbers etc.
		dumped_text = "===>"+arr+"<===("+typeof(arr)+")";
	}
	return dumped_text;
}


return;

var TimeSignature = require('./timesignature').TimeSignature;
// var ts = new tsm.TimeSignature();
var fs = require('fs');
var crypto = require('crypto');
var sys = require('sys');
var http = require('http');

var hashalg = 'sha256';

var b = fs.readFileSync('test.gtts');
var ts1 = TimeSignature(b);
console.log("Load from file: " + dump(ts1.verify()));


var hash = crypto.createHash(hashalg);
hash.update('Tere!');

var sserver = http.createClient(80, 'stamper.guardtime.net');
var reqdata = TimeSignature.composeRequest(new Buffer(hash.digest(), encoding='binary'), hashalg);
var request = sserver.request('POST', '/gt-signingservice', 
        {'host': 'stamper.guardtime.com', 
         'Content-Length': reqdata.length});
request.write(reqdata);
request.end();

request.on('response', function (response) {
    console.log('STATUS: ' + response.statusCode);
    var resp = new Buffer(5500), pos = 0;
    response.on('data', function(chunk){
    	resp.write(chunk.toString('binary'), pos, encoding='binary');
    	pos = pos + chunk.length;
     }).on('end', function(){
          var ts = new TimeSignature(TimeSignature.processResponse(resp.slice(0, pos)));
          console.log(dump(ts.verify()));
          // -continue here..
     });
});

