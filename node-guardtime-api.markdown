# Guardtime Node.js API

Module is split into two classes:

  * `TimeSignature` encapsulates signature token and offers some low-level 'static' methods;
  * `GuardTime` is service layer bridging tokens to Guardtime services.

TimeSignature is exported as guardtime.TimeSignature. Initialize and use like:

    var gt = require('guardtime');
    gt.conf({signeruri: 'http://my.gateway/gt-signingservice',
            verifieruri: 'http://my.gateway/gt-extendingservice'});

    gt.sign('some data', function (error, token){
        if (error)
            throw error;        
        console.log('Very secure time: ', token.getRegisteredTime());
        gt.verify('some data', token, function(error, checkflags, properties){
            if (error) throw error;
            console.log('Signature OK, signed by ' + properties.location_name);
        })
    });

If you need to store and retrieve the TimeSignature token then use something like

    arbitraryDatabase.putBlob(id, token.getContent());
    retrievedToken = new gt.TimeSignature(arbitraryDatabase.getBlob(id));

or

    gt.save('file.gtts', token, function (error){
        if (error) throw error;
        gt.load('file.gtts', function (error, retrievedToken){
            if (error) throw error;
            console.log('Loaded' + retrievedToken);
        });
    });



### Guardtime

* [Guardtime.js](#guardtime)
  * [conf](#conf)
  * [sign](#sign)
  * [signFile](#signfile)
  * [signHash](#signhash)
  * [verify](#verify)
  * [verifyFile](#verifyfile)
  * [verifyHash](#verifyHash)
      * [Signature Propertiess](#signature-properties)
  * [save](#save)
  * [load](#load)
  * [loadSync](#loadsync)
  * [extend](#extend)
  * [loadPublications](#loadpublications)
  * [Result Flags](#result-flags)

### Time Signature

* [Time Signature](#time-signature)
  * [TimeSignature](#timesignature)
  * [getContent](#getcontent)
  * [getRegisteredTime](#getregisteredtime)
  * [getSignerName](#getsignername)  
  * [getHashAlgorithm](#gethashalgorithm)
  * [Other Functions](#other-functions)

----

<a name="guardtime" />
## Guardtime

The Guardtime module offers access to signature and transport utilities. Most developers will rely on functions from this module almost exclusively.

Include this module in your code with:

```javascript
var gt = require('guardtime');
```
----

<a name="conf" />
### conf(configuration)

Allows for the use of a custom URI as the Gateway. The defaults are sufficient for general use. This value should be updated if you are using an internal Gateway.

__Arguments__

* configuration - Object containing fields specifying Gateway URI and publications lifetime. Fields are:
  * `signeruri` - Address of the Signing service
  * `verifieruri` - Address of the Extending service
  * `publicationsuri` - Address from which to download the publications file
  * `signerthreads` - Signing service connection pool max. size, i.e. max. number of parallel signing requests.
  * `verifierthreads` - Verifier service connection pool size.
  * `publicationsdata` - This is used internally and is automatically loaded if empty or expired
  * `publicationslifetime` - Number of seconds before we reload the publications file, default is 7 hours

__Example__

```javascript
//These are the default values
gt.conf({
  signeruri: 'http://stamper.guardtime.net/gt-signingservice', // or replace with private Gateway address
  verifieruri: 'http://verifier.guardtime.net/gt-extendingservice', // or replace with private Gateway address
  publicationsuri: 'http://verify.guardtime.com/gt-controlpublications.bin', // ok for most scenarios
  signerthreads: 16,    // Service connection pool size limit,
  verifierthreads: 2,   //   ie. max number of parallel network connections
  publicationsdata: '', // automatically loaded from publicationsuri if blank or expired
  publicationslifetime: 60*60*7 // seconds; if publicationsdata is older then it will be reloaded
});
```

----

<a name="sign" />
### sign(string, callback)

Signs the provided string. This will automatically calculate the hash of the provided string, using SHA256 as the hash algorithm. It will then send this hash to the Guardtime Signer, which will return a signature token. The signature token is passed to the callback function. This method is the complement of [verify()](#verify).

__Arguments__

* string - The string of data to be signed
* callback(error, token) - Called upon completion or in the event of an error. token is a TimeSignature object.

__Example__

```javascript
var data = "Hello, world";
gt.sign(data, function(err, token) {
  if(err)
    throw err;
  console.log('Signed at ' + token.getRegisteredTime());
  //Record the token
  arbitraryDb.putBlob(id, token.getContent());
});
```

----

<a name="signfile" />
### signFile(file, callback)

Similar to [sign()](#sign), except that this function calculates the hash of a file instead of a string. Uses default hash algorithm. It will then send this hash to the Guardtime Signer, which will return a signature token. The signature token is passed to the callback function. This method is the complement of [verifyFile()](#verifyfile).

__Arguments__

* file - String indicating the location of the file to be hashed
* callback(error, token) - Called upon completion or in the event of an error. 'token' is a TimeSignature object.

__Example__

```javascript
gt.signFile('/path/to/file', function(err, token) {
  if(err)
    throw err;
  console.log('Signed at ' + token.getRegisteredTime());
  //Record the token
  arbitraryDb.putBlob(id, token.getContent());
});
```

----

<a name="signhash" />
### signHash(hash, algorithm, callback)

Signs the given hash, using the specified hash algorithm. It will then send this hash to the Guardtime Signer, which will return a signature token. The signature token is passed to the callback function. This method is the complement of [verifyHash()](#verifyhash).

__Arguments__

* hash - Buffer or String containing the hash value of the data to be signed.
* algorithm - A string representing the algorithm that was used to sign the data. This must be correct or the signature may fail to validate in the future. Uses OpenSSL-style hash algorithm names (sha1, sha256, sha512 etc.)
* callback(error, token) - Called upon completion or in the event of an error. token is a TimeSignature object.

__Example__

```javascript
var data = 'Hello, world';
var hash = SomeHashFunction(data, 'SHA256'); //Some method of hashing.
gt.signHash(hash, 'SHA256', function(err, token) {
  if(err)
    throw err;
  console.log('Signed at ' + token.getRegisteredTime());
  //Record the token
  arbitraryDb.putBlob(id, token.getContent());
});
```

----

<a name="verify" />
### verify(string, token, callback)

This method verifies the given string against the given token, passing results to the callback function. This is the complement to [sign()](#sign).

__Arguments__

* string - A string containing data which will be hashed using SHA256 and compared against the token.
* token - The TimeSignature token generated when the data was originally signed.
* callback(error, result, properties) - Called upon completion or in the event of an error. 'result' is an integer assembled from a bitfield. Its fields are [included](#result-flags) in this document, but they do not need to be validated as an error will return an exception. 'properties' contains the data returned during the verification. Its fields are [below](#signature-properties).

__Example__

```javascript
var string = 'Hello, world';
var token = new gt.TimeSignature(arbitraryDb.getBlob(id));
gt.verify(string, token, function(err, result, properties) {
  if(err)
    throw err;
  console.log('Signed by ' + properties.location_id + ' at ' + properties.registered_time);
  //A full list of property values is included in this document
});
```

----

<a name="verifyFile" />
### verifyFile(file, token, callback)

This method verifies the given file against the given token, passing results to the callback function. This is the complement of [signFile()](#signfile).

__Arguments__

* file - A string indicating the location of the file to be hashed.
* token - The TimeSignature token generated when the data was successfully signed.
* callback(error, result, properties) - Called upon completion or in the event of an error. 'result' is an integer assembled from a bitfield. Its fields are [included](#result-flags) in this document, but they do not need to be validated as an error will return an exception. 'properties' contains the data returned during the verification. Its fields are [below](#signature-properties).

__Example__

```javascript
var token = new gt.TimeSignature(arbitraryDb.getBlob(id));
gt.verifyFile('/path/to/file', token, function(err, result, properties) {
  if(err)
    throw err;
  console.log('Signed by ' + properties.location_id + ' at ' + properties.registered_time);
  //A full list of property values is included in this document
});
```

----

<a name="verifyhash" />
### verifyHash(hash, algorithm, token, callback)

This method verifies the given hash against the given token, passing results to the callback function. This is the complement of [signHash()](#signhash).

__Arguments__

* hash - Buffer containing the hash value of the data to be signed.
* algorithm - A string representing the algorithm that was used to sign the data. This must be correct or the signature may fail to validate in the future. Uses OpenSSL-style hash algorithm names.
* callback(error, result, properties) - Called upon completion or in the event of an error. 'result' is an integer assembled from a bitfield. Its fields are [included](#result-flags) in this document, but they do not need to be validated as an error will return an exception. 'properties' contains the data returned during the verification. Its fields are [below](#signature-properties).

__Example__

```javascript
var data = 'Hello, world';
var hash = SomeHashFunction(data, 'SHA256'); //Some method of hashing.
var token = new gt.TimeSignature(arbitraryDb.getBlob(id));

gt.verifyHash(hash, token, token.getHashAlgorithm(), function(err, result, properties) {
  if(err)
    throw err;
  console.log('Signed by ' + properties.location_id + ' at ' + properties.registered_time);
  //A full list of property values is included in this document
});
```

----

<a name="signature-properties" />
#### Signature Properties:

- `verification_status` : flags about checks performed, see `resultflags` below.
- `location_id`: Numeric ID of issuing server (gateway), *trusted*. Obsolete.
- `location_name`: Human-readable ID of issuing server (gateway), *trusted* as it is set by upstream infrastructure and cannot be modified by gateway operator. Formatted as a ':' separated hierarchical list of entities; UTF-8 encoding.
- `registered_time`: Date object encapsulating *trusted* signing time/date.
- `policy`: Legally binding and audited signing policy OID.
- `hash_value`, `hash_algorithm`: Hash value of original signed doc, and name of used hash algorithm.
- `issuer_name`: Name of issuing server (gateway). May be changed by the gateway operator, take it as a 'label'.
- `public_key_fingerprint`: (present if 'PUBLIC_KEY_SIGNATURE_PRESENT'). Fingerprint of certificate used to sign the token; matches with whitelist published in _publications file_. Will be superseded with newspaper publication when it becomes available.
- `publication_string`: (this and following fields present if 'PUBLICATION_CHECKED'). Publication value used to validate the token, matches with newspaper publication value.
- `publication_time`, `publication_identifier`: Date object which encapsulates publishing time; _identifier_ is same encoding as Unix _time_t_ value.
- `pub_reference_list`: Human-readable pointers to trusted media which could be used to validate the _publication string_. Encoded as an array of UTF-8 strings.

**Note** that depending on publication data availability some fields may not be present.

----

<a name="save" />
### save(file, token, callback)

This is a simple utility to save a token to disk. It serializes a token and writes it out to the specified file. Note that if the given file already exists it may be overwritten. This method is asynchronous. It is the complement of [load()](#load).

__Arguments__

* file - A string indicating the location where the token should be saved.
* token - The TimeSignature token to be written to disc.
* callback(error) - Called upon completion or in the event of an error.

__Example__

```javascript
var token = getToken(); //Get a token

gt.save('/path/to/file', token, function(err) {
  if(err)
    throw err;
});
```

----

<a name="load" />
### load(file, callback)

This is the complement of [save()](#save). It will load a token from the specified file and return it to the callback function. This method is asynchronous.

__Arguments__

* file - A string indicating the location of a signature file.
* callback(error, token) - Called upon completion or in the event of an error. 'token' is a TimeSignature object containing the signature token.

__Example__

```javascript
gt.load('/path/to/file', function(err, token) {
  if(err)
    throw err;
  gt.verify('Hello, world', token, function(err, result, properties) {
    if(err)
      throw err;
    console.log('Greeting file was signed at: ' + properties.registered_time);
  });
});
```

----

<a name="loadsync" />
### loadSync(file)

This loads a token from a file *synchronously*. The TimeSignature token is returned directly.

__Arguments__

* file - A string indicating the location of the file to be loaded.

__Return__

* TimeSignature token - The TimeSignature token from that file.

__Throws__

* Exception - in the event of an error.

__Example__

```javascript
var token = gt.loadSync('/path/to/file');
```

----

<a name="extend" />
### extend(token, callback)

This function extends a given signature. It is primarily used internally and is called automatically when a signature is verified. A developer should generally not need to call this function directly.

__Arguments__

* token - The TimeSignature to be extended
* callback(error, token) - Returns the original token, not a new one. Note that an error does not necessarily mean that the signature is broken.

----

<a name="loadpublications" />
### loadPublications(callback)

This function loads or updates the publications file. This function is used internally. It is rare that a developer needs to call this directly, as it is called automatically in the event of an empty or expired publications file. 

__Arguments__

* callback(error) - Function to be called upon completion or in the event of an error.

----

<a name="result-flags" />
#### Result Flags

The following flags are present in callbacks from a [verify()](#verify) function. They are loaded as a bit field. Most developers will not need to consider these, they are checked automatically. The information here is also present in the 'properties' field of the callback. These are included primarily for backwards compatibility.

- `gt.VER_RES.PUBLIC_KEY_SIGNATURE_PRESENT`: Token is verified using RSA signature; newspaper publication is not yet available or accessible.
- `gt.VER_RES.PUBLICATION_REFERENCE_PRESENT`: Properties list includes human-readable array of newspapers or other trusted media references which could be used for independent signature verification.
- `gt.VER_RES.DOCUMENT_HASH_CHECKED`: Document content or hash was provided and it matches the hash value in signature token. Always present.
- `gt.VER_RES.PUBLICATION_CHECKED`: Token is verified using trusted publication which is printed in newspapers for independent verification.

----

<a name="time-signature" />
## TimeSignature

The TimeSignature module encapsulates a Guardime signature token. The following methods will be useful to developers:

---

<a name="timesignature" />
### TimeSignature(data)

Constructs a new TimeSignature from a serialized data blob, such as a blob retrieved from a database.

__Arguments__

* data - A binary blob, such as a blob from a database, either String or Buffer. This blob can be generated with [getContent()](#getcontent).

__Return__

* TimeSignature token - The TimeSignature token.

__Throws__

* Exception - in the event of an error.

__Example__

```javascript
var blob = arbitraryDb.getBlob(id);
var token = new gt.TimeSignature(blob);
```

---

<a name="getcontent" />
### getContent()

Returns the serialized form of a signature token. Useful when placing a signature into a database, sending over the network, etc.

__Return__

* Buffer buffer - The binary representation of the token.

__Throws__

* Exception - in the event of an error.

__Example__

```javascript
var token = getToken(); //Get a token
var blob = token.getContent();
arbitraryDb.putBlob(id, blob);
```

---

<a name="getregisteredtime" />
### getRegisteredTime()

Returns a Date object containing the time at which the token was registered. Useful if you need to check when a token was registered without calling verify().

__Return__

* Date registered_time - The date & time at which the object was registered.

__Example__

```javascript
var token = getToken(); //Get a token
var date = token.getRegisteredTime();
console.log('Signed at: ' + date);
```

----

<a name="getsignername" />
### getSignerName()

Returns signer's identity as ':' delimited hierarchial list of responsible authenticators.
If the token does not contain an identity then an empty string ('') is returned.

__Return__

* String signerid - Signer's identity 

__Example__

```javascript
var token = getToken(); //Get a token
var id = token.getSignerName();
console.log('Signed by: ' + id);
```


----

<a name="gethashalgorithm" />
### getHashAlgorithm()

Returns the name of the hash algorithm that was used to create the data in this token. The hash algorithm name is useful with functions such as [gt.verifyHash()](#verifyhash) -- comparing hash values is meaningful only if these hashes were created using same hash algorithm.

__Return__

* String hash_algorithm - The name of the algorithm that was used to create the hash in this token.

__Example__

```javascript
var token = getToken(); //Get a token
var algo = token.getHashAlgorithm();
console.log('Token generated using algorithm: ' + algo);
```

----

<a name="other-functions" />
### Other Functions

The following functions are most likely not interesting for general public.

---

###### `Object signature_properties = timesignature.verify()`
Verifies the internal consistency of the signature token and returns structure with signature properties. See `guardtime.verify()`. Throws an exception in case of error or 'broken' signature. Does not use network services.

###### `Boolean earlier = timesignature.isEarlierThan(TimeSignature ts2)`
Compares two signature tokens, returns True if encapsulated token is _provably_ older than one provided as an argument. False otherwise.

###### `Buffer request = timesignature.composeExtendingRequest()`
Creates a request data blob to be sent to the Verification service.

###### `Boolean extended = timesignature.isExtended()`
Returns True if timesignature token has all missing bits of hash-chain embedded for offline 
verification. False otherwise.

###### `Integer checks_done = timesignature.verifyHash(hash, String algo)`
Compares given hash to hash in signature token; only meaningful when hash algorithm is exactly same as signing hash algorithm (get with token.getHashAlgorithm()).
Returns a bitfield with verification information, constructed in the same format as above.
*Note* that validation of the return value is unnecessary, in case of errors or negative validation result an Exception is thrown.

###### `Boolean ok = timesignature.extend(response)`
Creates 'extended' version of TimeSignature token by including missing bits of the hash chain.
Input: Buffer or String with verification service response; returns True or throws an Exception.

###### 'static' functions for internal use:

`Buffer request = TimeSignature.composeRequest(hash, String hashalgorithm)`
Creates request data to be sent to signing service. Input: binary hash (Buffer or String) and hash algorithm name.

`Buffer der_token_content = TimeSignature.processResponse(response)`
Creates DER encoded serialized TimeSignature, usually fed to TimeSignature constructor.
Input: response from signing service.

`Boolean ok = TimeSignature.verifyPublications(der_publications_file_content)`
Verifies publications file (this is used by a higher level verification routine).
Returns True or throws exception.