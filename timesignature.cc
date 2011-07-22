#include <gt_base.h>
#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include <string.h>

using namespace node;
using namespace v8;


class TimeSignature: ObjectWrap
{
private:
  GTTimestamp *timestamp;
  
public:
  static Persistent<FunctionTemplate> constructor_template;
  
  static void Init(Handle<Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    constructor_template = Persistent<FunctionTemplate>::New(t);
    constructor_template->InstanceTemplate()->SetInternalFieldCount(1);
    constructor_template->SetClassName(String::NewSymbol("TimeSignature"));
    
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "verify", Verify);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "isExtended", IsExtended);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "getHashAlgorithm", GetHashAlgorithm);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "compareHash", CompareHash);
	NODE_SET_PROTOTYPE_METHOD(constructor_template, "checkPublication", CheckPublication);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "getSignerName", GetSignerName);   
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "getContent", GetContent);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "composeExtendingRequest", ComposeExtendingRequest);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "extend", Extend);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "isEarlierThan", IsEarlierThan);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "getRegisteredTime", GetRegisteredTime);

    NODE_SET_METHOD(constructor_template->GetFunction(), "composeRequest", ComposeRequest);
    NODE_SET_METHOD(constructor_template->GetFunction(), "processResponse", ProcessResponse);
    NODE_SET_METHOD(constructor_template->GetFunction(), "verifyPublications", VerifyPublications);

    
    target->Set(String::NewSymbol("TimeSignature"), constructor_template->GetFunction());

  }

  TimeSignature()
  {
  	 timestamp = NULL;
  }
  TimeSignature(GTTimestamp *ts)
  {
  	 timestamp = ts;
  }

  ~TimeSignature()
  {
  	if(timestamp != NULL)
  		GTTimestamp_free(timestamp);
  }
  
  static Handle<Value> New(const Arguments& args)
  {
  	if (!args.IsConstructCall()) {  
    	return FromConstructorTemplate(constructor_template, args);                                                                 
  	} 
    HandleScope scope;
    GTTimestamp *timestamp;
   
    if (!Buffer::HasInstance(args[0])) {
    return ThrowException(Exception::Error(
                String::New("First argument needs to be a Buffer")));
  	}                                                                                                                 
  	Local<Object> buffer_obj = args[0]->ToObject();                                                           
  	char *buffer_data = Buffer::Data(buffer_obj);                                                             
  	size_t buffer_length = Buffer::Length(buffer_obj);
    
    int res = GTTimestamp_DERDecode(buffer_data, buffer_length, &timestamp);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));

    TimeSignature *ts = new TimeSignature(timestamp);
    
  	ts->Wrap(args.This()); // or args.Holder()?                                                                                                      
                                                                                                                                
  	return args.This();
  }

  // no arguments, just syntax check
  static Handle<Value> Verify(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
            
	GTVerificationInfo *verification_info = NULL;
    int res = GTTimestamp_verify(ts->timestamp, 0, &verification_info);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));
                
    if (verification_info->verification_errors != GT_NO_FAILURES) {
        GTVerificationInfo_free(verification_info);
		return ThrowException(Exception::Error(
                String::New("TimeSignature verification error")));
	}  
	
	int result = verification_info->verification_status; // bitmap of checks done
    GTVerificationInfo_free(verification_info);

    return scope.Close(Integer::New(result));
  }


  static Handle<Value> IsExtended(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
                
	int res = GTTimestamp_isExtended(ts->timestamp);

    switch (res) {
    	case GT_EXTENDED:
    		return scope.Close(True());
    	case GT_NOT_EXTENDED:
    		return scope.Close(False());
    	default:
	    	return ThrowException(Exception::Error(
    	            String::New(GT_getErrorString(res))));                
  	}
  }
  
 
  // return openssl style hash alg name
  static Handle<Value> GetHashAlgorithm(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
    
    int alg;
	int res = GTTimestamp_getAlgorithm(ts->timestamp, &alg);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));               
  	
  	// ids copied from gt_base.h -> enum GTHashAlgorithm
   	switch(alg) {  
  		case 1: return scope.Close(String::New("SHA256"));
  		case 0: return scope.Close(String::New("SHA1"));
  		case 2: return scope.Close(String::New("RIPEMD160"));
  		case 3: return scope.Close(String::New("SHA224"));
  		case 4: return scope.Close(String::New("SHA384"));
  		case 5: return scope.Close(String::New("SHA512"));
  	   default:
    	 return ThrowException(Exception::Error(
                String::New("Unknown hash algorithm ID")));
   	} 
  	// using static func in gt_info.c: return scope.Close(String::New(hashAlgName(alg)));
  }

  static Handle<Value> GetRegisteredTime(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
               
	GTVerificationInfo *verification_info = NULL;
    int res = GTTimestamp_verify(ts->timestamp, 0, &verification_info);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));
                
    if (verification_info->verification_errors != GT_NO_FAILURES) {
        GTVerificationInfo_free(verification_info);
		return ThrowException(Exception::Error(
                String::New("TimeSignature verification error")));
	}  
	
	double result = verification_info->implicit_data->registered_time;
    GTVerificationInfo_free(verification_info);
    return scope.Close(NODE_UNIXTIME_V8(result)); // Date::New(time_t * 1000)
  }
  
    // ts.compareHash(binary hash in Buffer, algo)  -> bit flag
  static Handle<Value> CompareHash(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
    if (!Buffer::HasInstance(args[0])) {
    	return ThrowException(Exception::Error(
                String::New("First argument needs to be a Buffer containing binary digest")));
  	}
  	if (args.Length() == 2 && !args[1]->IsString()) {
    	return ThrowException(Exception::Error(String::New(
        	"Optional 2nd argument must be hash type as string")));
    }
    
    int hashalg_gt_id = 1;
    if (args.Length() == 2)
    	hashalg_gt_id = getAlgoID(*String::AsciiValue(args[1]->ToString()));

  	Local<Object> buffer_obj = args[0]->ToObject();                                                           
  	
    GTDataHash dh;
    dh.digest = NULL;
    dh.digest = (unsigned char *) Buffer::Data(buffer_obj);
    dh.digest_length = Buffer::Length(buffer_obj);
    dh.context = NULL;
    dh.algorithm = hashalg_gt_id;
  
    int res = GTTimestamp_checkDocumentHash(ts->timestamp, &dh);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));               
	return scope.Close(Integer::New(GT_DOCUMENT_HASH_CHECKED));
  }
  
      // ts.checkPublication(pub. file content in Buffer) -> true/exception
  static Handle<Value> CheckPublication(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
	if (!Buffer::HasInstance(args[0])) {
		return ThrowException(Exception::Error(
			String::New("First argument needs to be a Buffer with publications")));
	}
	Local<Object> buffer_obj = args[0]->ToObject();
	char *buffer_data = Buffer::Data(buffer_obj);                                                             
	size_t buffer_length = Buffer::Length(buffer_obj);
	
	GTPublicationsFile *pub;
	int res = GTPublicationsFile_DERDecode(buffer_data, buffer_length, &pub);
	if (res != GT_OK) 
		return ThrowException(Exception::Error(
			String::New(GT_getErrorString(res))));

	int ext = GTTimestamp_isExtended(ts->timestamp);	
	if (ext == GT_EXTENDED) 
	{
	    res = GTTimestamp_checkPublication(ts->timestamp, pub);    
	} 
	else if (ext == GT_NOT_EXTENDED) 
	{
		GTVerificationInfo *verification_info = NULL;
		res = GTTimestamp_verify(ts->timestamp, 0, &verification_info);
		if (res != GT_OK) {
			GTPublicationsFile_free(pub);
			return ThrowException(Exception::Error(
					String::New(GT_getErrorString(res))));
		}
					
		if (verification_info->verification_errors != GT_NO_FAILURES) {
			GTVerificationInfo_free(verification_info);
			GTPublicationsFile_free(pub);
			return ThrowException(Exception::Error(
					String::New("TimeSignature verification error")));
		}  
		
		GT_Time_t64 history_id = verification_info->implicit_data->registered_time;
		GTVerificationInfo_free(verification_info);		
		res = GTTimestamp_checkPublicKey(ts->timestamp, history_id, pub);	
	} 
	else 
	{
		GTPublicationsFile_free(pub);
		return ThrowException(Exception::Error(
			String::New(GT_getErrorString(ext))));	
	}
	
	GTPublicationsFile_free(pub);
	
	if (res != GT_OK)
		return ThrowException(Exception::Error(
			String::New(GT_getErrorString(res))));
			
	return scope.Close(Integer::New(GT_PUBLICATION_CHECKED));
  }
  
  static Handle<Value> GetSignerName(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
               
	GTVerificationInfo *verification_info = NULL;
    int res = GTTimestamp_verify(ts->timestamp, 0, &verification_info);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));
                
    if (verification_info->verification_errors != GT_NO_FAILURES) {
        GTVerificationInfo_free(verification_info);
		return ThrowException(Exception::Error(
                String::New("TimeSignature verification error")));
	}  	
	Local<String> result = String::New(
			verification_info->implicit_data->location_name ? 
			verification_info->implicit_data->location_name : "");
    GTVerificationInfo_free(verification_info);
    return scope.Close(result);
  }
 
  // returns DER encoded ts token
  static Handle<Value> GetContent(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
                
    unsigned char *data;
    size_t data_length;
    int res = GTTimestamp_getDEREncoded(ts->timestamp, &data, &data_length);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));
                
    Buffer *result = Buffer::New((char *)data, data_length);
    GT_free(data);
    return scope.Close(result->handle_);
  }
  
  // Buffer = composeExtendingRequest()
  static Handle<Value> ComposeExtendingRequest(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());
	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));

    unsigned char *request = NULL;                                                                      
    size_t request_length;
    
    int res = GTTimestamp_prepareExtensionRequest(ts->timestamp, &request, &request_length);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));
                
    Buffer *result = Buffer::New((char *)request, request_length);
    GT_free(request);
    return scope.Close(result->handle_);
  }
  
    // ts.extend(extending response)
    // returns true or throws an exception
  static Handle<Value> Extend(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());
	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
                
    if (!Buffer::HasInstance(args[0])) {
    	return ThrowException(Exception::Error(
                String::New("First argument needs to be a Buffer containing binary digest")));
  	}
  	
	Local<Object> buffer_obj = args[0]->ToObject();
	char *buffer_data = Buffer::Data(buffer_obj);                                                             
	size_t buffer_length = Buffer::Length(buffer_obj);
  	GTTimestamp *new_ts;
    int res = GTTimestamp_createExtendedTimestamp(ts->timestamp, buffer_data, buffer_length, &new_ts);
    if (res == GT_ALREADY_EXTENDED || res == GT_NONSTD_EXTEND_LATER ||
    		res == GT_NONSTD_EXTENSION_OVERDUE)
    	return scope.Close(Integer::New(res));
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));
                
    GTTimestamp_free(ts->timestamp);
    ts->timestamp = new_ts;
    
    return scope.Close(True());
  }
  
  
  static Handle<Value> IsEarlierThan(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());
	if (ts->timestamp == NULL)
		return ThrowException(Exception::Error(
                String::New("TimeSignature is blank")));
                
    if (!TimeSignature::HasInstance(args[0])) {
    	return ThrowException(Exception::Error(
                String::New("First argument needs to be a TimeSignature")));
  	}  	
  	TimeSignature *ts2 = ObjectWrap::Unwrap<TimeSignature>(args[0]->ToObject());  	
  	int res = GTTimestamp_isEarlierThan(ts->timestamp, ts2->timestamp);
    switch (res) {
    	case GT_EARLIER:
    		return scope.Close(True());
    	case GT_NOT_EARLIER:
    		return scope.Close(False());
    	default:
	    	return ThrowException(Exception::Error(
    	            String::New(GT_getErrorString(res))));                
  	}
  }
   


  
  // 'static class methods' below: ---------------- 
 
  //   req = TimeSignature.composeRequest(hash);
  // binary string will be represented as utf8, needs DecodeBytes/DecodeWrite. \0 is ok.
  // arg: binary hash as a Buffer; hashing or interaction of Hash object should be done in JS layer
  // second optional arg: hash algorithm name as openssl style string.
  static Handle<Value> ComposeRequest(const Arguments& args)
  {
    HandleScope scope;

    if (!Buffer::HasInstance(args[0])) {
    	return ThrowException(Exception::Error(
                String::New("First argument needs to be a Buffer containing binary digest")));
  	}
  	if (args.Length() == 2 && !args[1]->IsString()) {
    	return ThrowException(Exception::Error(String::New(
        	"Optional 2nd argument must be hash algorithm name as string")));
    }
    
    int hashalg_gt_id = 1;
    if (args.Length() == 2)
    	hashalg_gt_id = getAlgoID(*String::AsciiValue(args[1]->ToString()));

  	Local<Object> buffer_obj = args[0]->ToObject();                                                           
  	
    GTDataHash dh;
    dh.digest = NULL;
    dh.digest = (unsigned char *) Buffer::Data(buffer_obj);
    dh.digest_length = Buffer::Length(buffer_obj);
    dh.context = NULL;
    dh.algorithm = hashalg_gt_id;
    unsigned char *request = NULL;                                                                      
    size_t request_length;
    int res = GTTimestamp_prepareTimestampRequest(&dh, &request, &request_length);
    if (res != GT_OK) 
    	return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));
                
    Buffer *result = Buffer::New((char *)request, request_length);
    GT_free(request);
    return scope.Close(result->handle_);
  }
  
  
  // input: raw timestamper response in Buffer, output - DER token to be fed to constructor
  static Handle<Value> ProcessResponse(const Arguments& args)
  {
		HandleScope scope;
		if (!Buffer::HasInstance(args[0])) {
			return ThrowException(Exception::Error(
				String::New("First argument needs to be a Buffer")));
		}
		Local<Object> buffer_obj = args[0]->ToObject();
		char *buffer_data = Buffer::Data(buffer_obj);                                                             
		size_t buffer_length = Buffer::Length(buffer_obj);
	
	    GTTimestamp *timestamp;

		int res = GTTimestamp_createTimestamp(buffer_data, buffer_length, &timestamp);

		if (res != GT_OK) 
			return ThrowException(Exception::Error(
				String::New(GT_getErrorString(res))));
				
    	unsigned char *data;
    	size_t data_length;
    	res = GTTimestamp_getDEREncoded(timestamp, &data, &data_length);
  		GTTimestamp_free(timestamp);
    	if (res != GT_OK) 
    		return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));
                
    	Buffer *result = Buffer::New((char *)data, data_length);
    	GT_free(data);
    	return scope.Close(result->handle_);
	}
	
	// verifies and returns latest pub. date
  static Handle<Value> VerifyPublications(const Arguments& args)
  {
		HandleScope scope;
		if (!Buffer::HasInstance(args[0])) {
			return ThrowException(Exception::Error(
				String::New("First argument needs to be a Buffer")));
		}
		Local<Object> buffer_obj = args[0]->ToObject();
		char *buffer_data = Buffer::Data(buffer_obj);                                                             
		size_t buffer_length = Buffer::Length(buffer_obj);
		
		GTPublicationsFile *pub;
		int res = GTPublicationsFile_DERDecode(buffer_data, buffer_length, &pub);
		if (res != GT_OK) 
			return ThrowException(Exception::Error(
				String::New(GT_getErrorString(res))));
		
		GTPubFileVerificationInfo *vi;
		res = GTPublicationsFile_verify(pub,  &vi);
		if (res != GT_OK) {
			GTPublicationsFile_free(pub);
			return ThrowException(Exception::Error(
					String::New(GT_getErrorString(res))));
		}
		
		GTPublicationsFile_free(pub);
		double result = vi->last_publication_time;
		GTPubFileVerificationInfo_free(vi);

    	return scope.Close(NODE_UNIXTIME_V8(result)); // Date::New(time_t * 1000)

	}
	
  private:
	  static int getAlgoID(const char *algoName) {
        return (
                strcasecmp(algoName, "sha1") == 0 ? GT_HASHALG_SHA1 :
                strcasecmp(algoName, "sha224") == 0 ? GT_HASHALG_SHA224 :
                strcasecmp(algoName, "sha256") == 0 ? GT_HASHALG_SHA256 :
                strcasecmp(algoName, "sha384") == 0 ? GT_HASHALG_SHA384 :
                strcasecmp(algoName, "sha512") == 0 ? GT_HASHALG_SHA512 :
                strcasecmp(algoName, "ripemd160") == 0 ? GT_HASHALG_RIPEMD160 :
                -1);
   }
   
   static bool HasInstance(v8::Handle<v8::Value> val) {
  	if (!val->IsObject()) return false;
  	Local<Object> obj = val->ToObject();

  	if (obj->GetIndexedPropertiesExternalArrayDataType() == kExternalUnsignedByteArray)
    	return true;
	if (constructor_template->HasInstance(obj)) 
    	return true;
  	return false;
  }	
};

Persistent<FunctionTemplate> TimeSignature::constructor_template;

extern "C" {
  static void init (Handle<Object> target)
  {
    GT_init();
    TimeSignature::Init(target);      
  }

  NODE_MODULE(timesignature, init);
}
