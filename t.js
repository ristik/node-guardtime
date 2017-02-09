var gt = require('./guardtime');



gt.sign('Hello world!', function(err, ts) {
  if (err)
    throw err;
  gt.verify('Hello world!', ts, function(err, checkflags, props){
    if (err) 
      throw err;
    console.log('All ok; signed by ' + props.location_name + ' at ' + props.registered_time);
  });
});
