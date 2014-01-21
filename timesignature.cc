/*
 * Copyright 2014 Guardtime AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

// openssl is depreciated on a closing up platform.
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_5

#include <gt_base.h>
#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>

#ifdef BUNDLED_LIBGT
  #include "node_root_certs.h"
#endif

// from node_crypo.cc
#define ASSERT_IS_STRING_OR_BUFFER(val) \
if (!val->IsString() && !Buffer::HasInstance(val)) { \
return ThrowException(Exception::TypeError(String::New("Not a string or buffer"))); \
}

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
    HandleScope scope;
    GTTimestamp *timestamp;
    int res;

    if (!args.IsConstructCall())
      return ThrowException(String::New("Please use 'new' to instantiate a TimeSignature class"));

    if (args.Length() != 1)
      return ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));

    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    ssize_t len = DecodeBytes(args[0], BINARY);
    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    if (Buffer::HasInstance(args[0])) {
      Local<Object> buffer_obj = args[0]->ToObject();
      char *buffer_data = Buffer::Data(buffer_obj);
      size_t buffer_length = Buffer::Length(buffer_obj);
      res = GTTimestamp_DERDecode(buffer_data, buffer_length, &timestamp);
    } else {
      char* buf = new char[len];
      ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
      assert(written == len);
      res = GTTimestamp_DERDecode(buf, len, &timestamp);
      delete [] buf;
    }
    if (res != GT_OK)
      return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));

    TimeSignature *ts = new TimeSignature(timestamp);

    ts->Wrap(args.This());
    return args.This();
  }

  static Local<String> format_location_id(GT_UInt64 l)
  {
    char buf[32];
    if (l == 0)
      return String::New("");
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
            (unsigned) (l >> 48 & 0xffff),
            (unsigned) (l >> 32 & 0xffff),
            (unsigned) (l >> 16 & 0xffff),
            (unsigned) (l & 0xffff)); 
    return String::New(buf);
  }
  
  static Local<String> hash_algorithm_name_as_String(int alg) 
  {
      // ids copied from gt_base.h -> enum GTHashAlgorithm
      // there is static func in gt_info.c: hashAlgName(alg));
    switch(alg) {  
      case 1: return String::New("SHA256");
      case 0: return String::New("SHA1");
      case 2: return String::New("RIPEMD160");
      case 3: return String::New("SHA224");
      case 4: return String::New("SHA384");
      case 5: return String::New("SHA512");
      default:
        return String::New("<unknown or untrusted hash algorithm>");
    }    
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
    int res = GTTimestamp_verify(ts->timestamp, 1, &verification_info);
    if (res != GT_OK)
      return ThrowException(Exception::Error(
                String::New(GT_getErrorString(res))));

    if (verification_info->verification_errors != GT_NO_FAILURES) {
        GTVerificationInfo_free(verification_info);
        return ThrowException(Exception::Error(
                String::New("TimeSignature verification error")));
    }

    Handle<Object> result = Object::New();
    result->Set(String::New("verification_status"), Integer::New(verification_info->verification_status));
    result->Set(String::New("location_id"), format_location_id(verification_info->implicit_data->location_id));
    // result->Set(String::New("location_id"), Number::New(verification_info->implicit_data->location_id));
    if (verification_info->implicit_data->location_name != NULL)
      result->Set(String::New("location_name"), String::New(verification_info->implicit_data->location_name));
    result->Set(String::New("registered_time"), NODE_UNIXTIME_V8(verification_info->implicit_data->registered_time));

    if (verification_info->explicit_data->policy != NULL)
      result->Set(String::New("policy"), String::New(verification_info->explicit_data->policy));
    result->Set(String::New("hash_algorithm"), hash_algorithm_name_as_String(verification_info->explicit_data->hash_algorithm));
    if (verification_info->explicit_data->hash_value != NULL)
      result->Set(String::New("hash_value"), String::New(verification_info->explicit_data->hash_value));
    if (verification_info->explicit_data->issuer_name != NULL)
      result->Set(String::New("issuer_name"), String::New(verification_info->explicit_data->issuer_name));

    // not extended:
    if (verification_info->implicit_data->public_key_fingerprint != NULL)
      result->Set(String::New("public_key_fingerprint"), String::New(verification_info->implicit_data->public_key_fingerprint));

    // extended:
    if (verification_info->implicit_data->publication_string != NULL) {
      result->Set(String::New("publication_string"), String::New(verification_info->implicit_data->publication_string));
      result->Set(String::New("publication_identifier"), Number::New(verification_info->explicit_data->publication_identifier));
      result->Set(String::New("publication_time"), NODE_UNIXTIME_V8(verification_info->explicit_data->publication_identifier));

      Handle<Array> refarr = Array::New(verification_info->explicit_data->pub_reference_count);
      for (int i = 0; i < verification_info->explicit_data->pub_reference_count; i++)
        refarr->Set(i, String::New(verification_info->explicit_data->pub_reference_list[i]));
      result->Set(String::New("pub_reference_list"), refarr);
    }

    GTVerificationInfo_free(verification_info);
    return scope.Close(result);
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

    return scope.Close(hash_algorithm_name_as_String(alg));    
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
    return scope.Close(NODE_UNIXTIME_V8(result));
  }

    // ts.compareHash(binary hash in Buffer, algo)  -> bit flag
  static Handle<Value> CompareHash(const Arguments& args)
  {
    HandleScope scope;
    TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This());

    if (ts->timestamp == NULL)
      return ThrowException(Exception::Error(
            String::New("TimeSignature is blank")));

    if (args.Length() < 1 || args.Length() > 2) {
      return ThrowException(Exception::TypeError(String::New("Bad parameter")));
    }
    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    if (args.Length() == 2 && !args[1]->IsString()) {
      return ThrowException(Exception::TypeError(String::New(
          "Optional 2nd argument must be hash type as string")));
    }
    ssize_t len = DecodeBytes(args[0], BINARY);
    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    int hashalg_gt_id = 1;
    if (args.Length() == 2)
      hashalg_gt_id = getAlgoID(*String::Utf8Value(args[1]->ToString()));

    if (hashalg_gt_id < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Unsupported hash algorithm"));
      return ThrowException(exception);
    }
    GTDataHash dh;
    dh.context = NULL;
    dh.algorithm = hashalg_gt_id;
    int res;
    if (Buffer::HasInstance(args[0])) {
      Local<Object> buffer_obj = args[0]->ToObject();
      dh.digest = (unsigned char *) Buffer::Data(buffer_obj);
      dh.digest_length = len;
      res = GTTimestamp_checkDocumentHash(ts->timestamp, &dh);
    } else {  // string
      char* buf = new char[len];
      ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
      assert(written == len);
      dh.digest = (unsigned char*) buf;
      dh.digest_length = len;
      res = GTTimestamp_checkDocumentHash(ts->timestamp, &dh);
      delete [] buf;
    }

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

    if (args.Length() != 1)
      return ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));

    ASSERT_IS_STRING_OR_BUFFER(args[0]);
    ssize_t len = DecodeBytes(args[0], BINARY);
    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    int res;
    GTPublicationsFile *pub;
    if (Buffer::HasInstance(args[0])) {
      Local<Object> buffer_obj = args[0]->ToObject();
      char *buffer_data = Buffer::Data(buffer_obj);
      res = GTPublicationsFile_DERDecode(buffer_data, len, &pub);
    } else {
      char* buf = new char[len];
      ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
      assert(written == len);
      res = GTPublicationsFile_DERDecode(buf, len, &pub);
      delete [] buf;
    }
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
          (verification_info->implicit_data->location_name != NULL) ?
            verification_info->implicit_data->location_name :
            "");
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

    if (args.Length() != 1) {
      return ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    }

    ASSERT_IS_STRING_OR_BUFFER(args[0]);
    ssize_t len = DecodeBytes(args[0], BINARY);
    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    int res;
    GTTimestamp *new_ts;
    if (Buffer::HasInstance(args[0])) {
      Local<Object> buffer_obj = args[0]->ToObject();
      char *buffer_data = Buffer::Data(buffer_obj);
      size_t buffer_length = Buffer::Length(buffer_obj);
      res = GTTimestamp_createExtendedTimestamp(ts->timestamp, buffer_data, buffer_length, &new_ts);
    } else {
      char* buf = new char[len];
      ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
      assert(written == len);
      res = GTTimestamp_createExtendedTimestamp(ts->timestamp, buf, len, &new_ts);
      delete [] buf;
    }
    if (res == GT_ALREADY_EXTENDED || res == GT_NONSTD_EXTEND_LATER || res == GT_NONSTD_EXTENSION_OVERDUE)
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

    if (args.Length() < 1 || args.Length() > 2) {
      return ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    }
    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    if (args.Length() == 2 && !args[1]->IsString()) {
      return ThrowException(Exception::TypeError(String::New(
            "Optional 2nd argument must be hash algorithm name as string")));
    }
    ssize_t len = DecodeBytes(args[0], BINARY);
    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    int hashalg_gt_id = 1;
    if (args.Length() == 2)
      hashalg_gt_id = getAlgoID(*String::Utf8Value(args[1]->ToString()));
    if (hashalg_gt_id < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Unsupported hash algorithm"));
      return ThrowException(exception);
    }
    
    GTDataHash dh;
    dh.context = NULL;
    dh.algorithm = hashalg_gt_id;
    unsigned char *request = NULL;
    size_t request_length;
    int res;
    if (Buffer::HasInstance(args[0])) {
      Local<Object> buffer_obj = args[0]->ToObject();
      dh.digest = (unsigned char *) Buffer::Data(buffer_obj);
      dh.digest_length = Buffer::Length(buffer_obj);
      res = GTTimestamp_prepareTimestampRequest(&dh, &request, &request_length);
    } else {  // string
      char* buf = new char[len];
      ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
      assert(written == len);
      dh.digest = (unsigned char*) buf;
      dh.digest_length = len;
      res = GTTimestamp_prepareTimestampRequest(&dh, &request, &request_length);
      delete [] buf;
    }
    if (res != GT_OK)
      return ThrowException(Exception::Error(
            String::New(GT_getErrorString(res))));

    //   How to return  String:
    //Local<Value> outString;
    //outString = Encode(request, request_length, BINARY);
    //GT_free(request);
    //return scope.Close(outString);
    //   instead we return Buffer:
    Buffer *result = Buffer::New((char *)request, request_length);
    GT_free(request);
    return scope.Close(result->handle_);
  }


    // input: raw timestamper response in Buffer, output - DER token to be fed to constructor
  static Handle<Value> ProcessResponse(const Arguments& args)
  {
    HandleScope scope;

    if (args.Length() != 1) {
      return ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    }

    ASSERT_IS_STRING_OR_BUFFER(args[0]);
    ssize_t len = DecodeBytes(args[0], BINARY);
    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    int res;
    GTTimestamp *timestamp;
    if (Buffer::HasInstance(args[0])) {
      Local<Object> buffer_obj = args[0]->ToObject();
      char *buffer_data = Buffer::Data(buffer_obj);
      res = GTTimestamp_createTimestamp(buffer_data, len, &timestamp);
    } else {
      char* buf = new char[len];
      ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
      assert(written == len);
      res = GTTimestamp_createTimestamp(buf, len, &timestamp);
      delete [] buf;
    }
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

    if (args.Length() != 1)
      return ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    ASSERT_IS_STRING_OR_BUFFER(args[0]);
    ssize_t len = DecodeBytes(args[0], BINARY);
    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    bool bufferAllocated = false;
    char *buf;
    if (Buffer::HasInstance(args[0])) {
      Local<Object> buffer_obj = args[0]->ToObject();
      buf = Buffer::Data(buffer_obj);
    } else {
      buf = new char[len];
      bufferAllocated = true;
      ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
      assert(written == len);
    }

    GTPublicationsFile *pub;
    int res = GTPublicationsFile_DERDecode(buf, len, &pub);
    if (bufferAllocated)
      delete [] buf;
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

    return scope.Close(NODE_UNIXTIME_V8(result));

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
  extern X509_STORE *GT_truststore;

  static void init (Handle<Object> target)
  {
    GT_init();
    TimeSignature::Init(target);

    // If using bundled GT C API then use Node's root certificates to validate signature on
    // publications file.
#ifdef BUNDLED_LIBGT
    //GTTruststore_init(0); // triggers assert() if called
    if (!GT_truststore)
      GT_truststore = X509_STORE_new();

    for (int i = 0; root_certs[i]; i++) {
      BIO *bp = BIO_new(BIO_s_mem());

      if (!BIO_write(bp, root_certs[i], strlen(root_certs[i]))) {
        BIO_free(bp);
        return;
      }

      X509 *x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);

      if (x509 == NULL) {
        BIO_free(bp);
        return;
      }

      X509_STORE_add_cert(GT_truststore, x509);

      BIO_free(bp);
      X509_free(x509);
    }
#endif
  }

  NODE_MODULE(timesignature, init);
}
