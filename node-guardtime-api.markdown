# GuardTime Node.js API

Module is split into two classes:

  * `TimeSignature` encapsulates signature token and offers some low-level 'static' methods;
  * `GuardTime` is service layer bridging tokens to GuardTime services.

TimeSignature is exported as guardtime.TimeSignature. Initialize like:

    var gt = require('guardtime');
    gt.conf({signeruri: 'http://my.gateway/gt-signingservice',
            verifieruri: 'http://my.gateway/gt-extendingservice'});
    gt.sign('some data', function(error, token){
        if (error)
            throw error;
        else
            console.log('Very secure time: ', token.getRegisteredTime());
    });


## module GuardTime

### gt.conf(properties)
Optionally change service configuration, all parameters are optional. Defaults:

    gt.conf({
            signeruri: 'http://stamper.guardtime.net/gt-signingservice',       // or private GW here
            verifieruri: 'http://verifier.guardtime.net/gt-extendingservice',  // or private GW here
            publicationsuri: 'http://verify.guardtime.com/gt-controlpublications.bin',  // ok for most scenarios
            publicationsdata: <automatically loaded from publicationsuri if not present>,
            publicationslifetime: 60*60*7      // seconds; if publicationsdata is older then it will be reloaded
        });

### gt.sign(String data, function(Exception error, TimeSignature ts){});
### gt.signFile(String filename, function(Exception error, TimeSignature ts){});
### gt.signHash(binary_hash, String hashalgo, function(Exception error, TimeSignature ts){});
  
Signs data, creates TimeSignature token and returns it as 2nd argument to the callback.

### gt.save(String filename, TimeSignature ts, function(Exception error)[]);
Saves signature token to file, asyncronously.

### gt.load(String filename, function(Exception error, TimeSignature ts){});
Loads and creates signature token from file.

### TimeSignature ts = gt.loadSync(String filename);
Loads and creates signature token from file, asynchronously.

### gt.verify(String data, TimeSignature ts, function(Exception err, Integer resultflags, properties){});
### gt.verifyFile(String filename, TimeSignature ts, function(Exception err, Integer resultflags, properties){});
### gt.verifyHash(binary_hash, String hashalg, TimeSignature ts, function(Exception err, Integer resultflags, properties){});
Verifies signature token. Callback gets Exception in case of any errors. On success the callback gets back flags about the checks
performed, and extracted signature properties. There is no need to verify result flags as the list of necessary checks 
is hardcoded and exception is returned in case of any errors. Possible result flags (bits set in integer) are:

  - `gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT`: Token is verified using RSA signature; newspaper publication is not yet available or
accessible.

  - `gt.VER_RES.PUBLICATION_REFERENCE_PRESENT`: Properties list includes human-readable array of newspapers or other
trusted media which could be used for independent signature verification.

  - `gt.VER_RES.DOCUMENT_HASH_CHECKED`: Document content or hash was provided and it matches the hash value in signature token.
Always present.

  - `gt.VER_RES.PUBLICATION_CHECKED`: Token is verified using trusted publication which is printed in newspapers for independent
verification.

Signature properties structure is populated with following fields:

  - `verification_status`: flags about the checks performed, see `resultflags` above.

  - `location_id`: Numeric ID of issuing server (gateway), *trusted*.

  - `location_name`: Human-readable ID of issuing server (gateway), *trusted* as it is set by upstream infrastructure and
cannot be tampered by gateway operatur. Formatted as ':' - separated hierarchical list of entities; UTF-8 encoding.

  - `registered_time`: Date object encapsulating *trusted* signing time/date.

  - `policy`: Legally binding and audited signing policy OID.

  - `hash_value`, `hash_algorithm`: Hash value of original signed doc, and name of used hash algorithm.

  - `issuer_name`: Name of issuing server (gateway). May be changed by the gateway itself, take it as a 'label'.

  - `public_key_fingerprint`: (present if 'PUBLIC_KEY_SIGNATURE_PRESENT'). Fingerprint of certificate used to sign the token; matches
with whitelist published in _publications file_. Will be superceded with newspaper publication when it becomes available.

  - `publication_string`: (this and following fields present if 'PUBLICATION_CHECKED'). Publication value used to validate the token,
matches with newspaper publication value.

  - `publication_time`, `publication_identifier`: Date object which encapsulates publishing time; _identifier_ is same encoded as
unix _time_t_ value.

  - `pub_reference_list`: Human-readable pointers to trusted media which could be used to validate the _publication string_.
Encoded as array of UTF-8 strings.

Note that depending on data availability some fields may be not present.


### gt.loadPublications(function(Exception error){});
Loads publications data form network and saves it in GuardTime object for future verification use.
Note that all verification functions need this data and call this function if it is not done explicitly.
It is advised to refresh publications data after approx. every 6 hours.
Callback will be called when loading is done; error is null in the case of success.

### gt.extend(TimeSignature ts, function(Exception error, TimeSignature ts){});
Creates 'extended' form of TimeSignature token, ready for hash-chain based verification.
Mostly for internal use. Does not create new TimeSignature token; modifies the original.
Note that if callback returns error object then signature must not be considered as broken as it 
could still be verified (offline).



## module TimeSignature

### constructor ts = new TimeSignature(der_token_content);
Creates new timesignature token from DER-encoded serialized representation (for example file on disk)

### Buffer req = ts.composeExtendingRequest();
Creates request data blob to be sent to Verification service.

### signature_properties = ts.verify();
Verifies internal consistency of signature token and returns structure with signature properties 
(see `GuardTime.verify()` above), or throws an exception in case of error or 'broken' signature.

### Boolean earlier = ts.isEarlierThan(TimeSignature ts2);
Compares two signature tokens; returns True if encapsulated token is provably earlier than one 
provided as an argument.

### Date date = ts.getRegisteredTime();
Returns provably secure signature registration time as Date object, with 1 second resolution.

### String s = ts.getSignerName();
Returns signer's identity as ':' - separated hierarchical list of responsible authenticators.
If token does not contain identity then '' (empty string) is returned.

### Boolean extended = ts.isExtended();
Returns True if timesignature token has all missing bits of hash-chain embedded for offline 
verification.

### String algo_name = ts.getHashAlgorithm();
Returns OpenSSL style hash algorithm name. Necessary for verification - data has to be hashed with
same alg.

### Integer checks_done = ts.verifyHash(hash, String algo='sha256');
Compares hash to one in signature token; makes sense only if hashing algorithms are same.

### Integer checks_done = ts.checkPublication(pub_data);
Verifies timesignature token using data in publications file; returns check flags or throws an 
exception on error.

### Buffer data_blob = ts.getContent();
Returns serialized DER representation of TimeSignature token.

### Boolean ok = ts.extend(response);
Creates 'extended' version of timesignature token, by including missing bits of the hash-chain.
Input: Buffer or string with verification service response; returns True or throws an exception.


### 'static' functions for internal use:

    Buffer req = TimeSignature.composeRequest(hash, String alg='sha256);
Creates request data to be sent to signing service. Input: binary hash and hash alg. name.

    Buffer der_token_content = TimeSignature.processResponse(resp);
Creates DER encoded serialized timesignature, usually fed to TimeSignature constructor.
Input: response from signing service.

    Bool ok = TimeSignature.verifyPublications(der_publications_file_content);
Verifies publications file (used by higher level verification routines).
Returns True or throws exception.
