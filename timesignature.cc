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

// openssl is deprecated on a closing up platform.
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_5

#include <gt_base.h>
#include <node.h>
#include <node_buffer.h>
#include <node_object_wrap.h>

#include <nan.h>
#include <string>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#if !(defined OPENSSL_CA_FILE || defined OPENSSL_CA_DIR || defined PREINSTALLED_LIBGT)
  const char* root_certs[] = {
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEGjCCAwICEQCLW3VWhFSFCwDPrzhIzrGkMA0GCSqGSIb3DQEBBQUAMIHKMQsw\n"
    "CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZl\n"
    "cmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAxOTk5IFZlcmlTaWdu\n"
    "LCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlT\n"
    "aWduIENsYXNzIDEgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3Jp\n"
    "dHkgLSBHMzAeFw05OTEwMDEwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQswCQYD\n"
    "VQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlT\n"
    "aWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAxOTk5IFZlcmlTaWduLCBJ\n"
    "bmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWdu\n"
    "IENsYXNzIDEgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkg\n"
    "LSBHMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN2E1Lm0+afY8wR4\n"
    "nN493GwTFtl63SRRZsDHJlkNrAYIwpTRMx/wgzUfbhvI3qpuFU5UJ+/EbRrsC+MO\n"
    "8ESlV8dAWB6jRx9x7GD2bZTIGDnt/kIYVt/kTEkQeE4BdjVjEjbdZrwBBDajVWjV\n"
    "ojYJrKshJlQGrT/KFOCsyq0GHZXi+J3x4GD/wn91K0zM2v6HmSHquv4+VNfSWXjb\n"
    "PG7PoBMAGrgnoeS+Z5bKoMWznN3JdZ7rMJpfo83ZrngZPyPpXNspva1VyBtUjGP2\n"
    "6KbqxzcSXKMpHgLZ2x87tNcPVkeBFQRKr4Mn0cVYiMHd9qqnoxjaaKptEVHhv2Vr\n"
    "n5Z20T0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAq2aN17O6x5q25lXQBfGfMY1a\n"
    "qtmqRiYPce2lrVNWYgFHKkTp/j90CxObufRNG7LRX7K20ohcs5/Ny9Sn2WCVhDr4\n"
    "wTcdYcrnsMXlkdpUpqwxga6X3s0IrLjAl4B/bnKk52kTlWUfxJM8/XmPBNQ+T+r3\n"
    "ns7NZ3xPZQL/kYVUc8f/NveGLezQXk//EZ9yBta4GvFMDSZl4kSAHsef493oCtrs\n"
    "pSCAaWihT37ha88HQfqDjrw43bAuEbFrskLMmrz5SCJ5ShkPshw+IHTZasO+8ih4\n"
    "E1Z5T21Q6huwtVexN2ZYI/PcD98Kh8TvhgXVOBRgmaNL3gaWcSzy27YfpO8/7g==\n"
    "-----END CERTIFICATE-----\n",
    NULL
  };
    // #include "node_root_certs.h" // does not work since node 0.10
#endif


// from node_crypo.cc
#define ASSERT_IS_STRING_OR_BUFFER(val) \
  if (!val->IsString() && !Buffer::HasInstance(val)) { \
    return NanThrowTypeError("Not a string or buffer"); \
  }

#define ASSERT_IS_N_ARGS(val) \
  if (args.Length() != (val)) { \
    return NanThrowTypeError("Wrong number of arguments"); \
  }

#define ASSERT_IS_POSITIVE(val) \
  if ((val) < 0) { \
    return NanThrowTypeError("Bad argument"); \
  }

#define UNWRAP_ts() \
  TimeSignature* ts = ObjectWrap::Unwrap<TimeSignature>(args.This()); \
  if (ts->timestamp == NULL) { \
    return NanThrowError("TimeSignature is blank"); \
  }

#define ASSERT_GT_ERROR(res) \
  if ((res) != GT_OK) { \
    return NanThrowError(GT_getErrorString(res)); \
  }


using namespace node;
using namespace v8;


class TimeSignature: public ObjectWrap
{
private:
  GTTimestamp *timestamp;

public:
  static Persistent<FunctionTemplate> constructor_template;

  static void Init(Handle<Object> target)
  {
    NanScope();

    Local<FunctionTemplate> t = NanNew<FunctionTemplate>(New);
    NanAssignPersistent(constructor_template, t);
    t->InstanceTemplate()->SetInternalFieldCount(1);
    t->SetClassName(NanNew<String>("TimeSignature"));

    NODE_SET_PROTOTYPE_METHOD(t, "verify", Verify);
    NODE_SET_PROTOTYPE_METHOD(t, "isExtended", IsExtended);
    NODE_SET_PROTOTYPE_METHOD(t, "getHashAlgorithm", GetHashAlgorithm);
    NODE_SET_PROTOTYPE_METHOD(t, "compareHash", CompareHash);
    NODE_SET_PROTOTYPE_METHOD(t, "checkPublication", CheckPublication);
    NODE_SET_PROTOTYPE_METHOD(t, "getSignerName", GetSignerName);
    NODE_SET_PROTOTYPE_METHOD(t, "getContent", GetContent);
    NODE_SET_PROTOTYPE_METHOD(t, "composeExtendingRequest", ComposeExtendingRequest);
    NODE_SET_PROTOTYPE_METHOD(t, "extend", Extend);
    NODE_SET_PROTOTYPE_METHOD(t, "isEarlierThan", IsEarlierThan);
    NODE_SET_PROTOTYPE_METHOD(t, "getRegisteredTime", GetRegisteredTime);

    NODE_SET_METHOD(t, "composeRequest", ComposeRequest);
    NODE_SET_METHOD(t, "processResponse", ProcessResponse);
    NODE_SET_METHOD(t, "verifyPublications", VerifyPublications);

    target->Set(NanNew("TimeSignature"), t->GetFunction());
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

  static NAN_METHOD(New)
  {
    NanScope();
    GTTimestamp *timestamp;
    int res;

    if (!args.IsConstructCall())
      return NanThrowError("Please use 'new' to instantiate a TimeSignature class");

    ASSERT_IS_N_ARGS(1);
    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    ssize_t len = DecodeBytes(args[0], BINARY);
    ASSERT_IS_POSITIVE(len);
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
    ASSERT_GT_ERROR(res);

    TimeSignature *ts = new TimeSignature(timestamp);

    ts->Wrap(args.This());
    NanReturnValue(args.This());
  }

  static Local<String> format_location_id(GT_UInt64 l)
  {
    char buf[32];
    if (l == 0)
      return NanNew<String>("");
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
            (unsigned) (l >> 48 & 0xffff),
            (unsigned) (l >> 32 & 0xffff),
            (unsigned) (l >> 16 & 0xffff),
            (unsigned) (l & 0xffff)); 
    return NanNew<String>(buf);
  }
  
  static Local<String> hash_algorithm_name_as_String(int alg) 
  {
      // ids copied from gt_base.h -> enum GTHashAlgorithm
      // there is static func in gt_info.c: hashAlgName(alg));
    switch(alg) {  
      case 1: return NanNew<String>("SHA256");
      case 0: return NanNew<String>("SHA1");
      case 2: return NanNew<String>("RIPEMD160");
      case 3: return NanNew<String>("SHA224");
      case 4: return NanNew<String>("SHA384");
      case 5: return NanNew<String>("SHA512");
      default:
        return NanNew<String>("<unknown or untrusted hash algorithm>");
    }    
  }

  // no arguments, just syntax check
  static NAN_METHOD(Verify)
  {
    NanScope();
    UNWRAP_ts();

    GTVerificationInfo *verification_info = NULL;
    int res = GTTimestamp_verify(ts->timestamp, 1, &verification_info);
    ASSERT_GT_ERROR(res);

    if (verification_info->verification_errors != GT_NO_FAILURES) {
        GTVerificationInfo_free(verification_info);
        return NanThrowError("TimeSignature verification error");
    }

    Local<Object> result = NanNew<Object>();
    result->Set(NanNew<String>("verification_status"), NanNew<Integer>(verification_info->verification_status));
    result->Set(NanNew<String>("location_id"), format_location_id(verification_info->implicit_data->location_id));
    if (verification_info->implicit_data->location_name != NULL)
      result->Set(NanNew<String>("location_name"), NanNew<String>(verification_info->implicit_data->location_name));
    result->Set(NanNew<String>("registered_time"), NODE_UNIXTIME_V8(verification_info->implicit_data->registered_time));

    if (verification_info->explicit_data->policy != NULL)
      result->Set(NanNew<String>("policy"), NanNew<String>(verification_info->explicit_data->policy));
    result->Set(NanNew<String>("hash_algorithm"), hash_algorithm_name_as_String(verification_info->explicit_data->hash_algorithm));
    if (verification_info->explicit_data->hash_value != NULL)
      result->Set(NanNew<String>("hash_value"), NanNew<String>(verification_info->explicit_data->hash_value));
    if (verification_info->explicit_data->issuer_name != NULL)
      result->Set(NanNew<String>("issuer_name"), NanNew<String>(verification_info->explicit_data->issuer_name));

    // not extended:
    if (verification_info->implicit_data->public_key_fingerprint != NULL)
      result->Set(NanNew<String>("public_key_fingerprint"), NanNew<String>(verification_info->implicit_data->public_key_fingerprint));

    // extended:
    if (verification_info->implicit_data->publication_string != NULL) {
      result->Set(NanNew<String>("publication_string"), NanNew<String>(verification_info->implicit_data->publication_string));
      result->Set(NanNew<String>("publication_identifier"), NanNew<Number>(verification_info->explicit_data->publication_identifier));
      result->Set(NanNew<String>("publication_time"), NODE_UNIXTIME_V8(verification_info->explicit_data->publication_identifier));

      Handle<Array> refarr = NanNew<Array>(verification_info->explicit_data->pub_reference_count);
      for (int i = 0; i < verification_info->explicit_data->pub_reference_count; i++)
        refarr->Set(i, NanNew<String>(verification_info->explicit_data->pub_reference_list[i]));
      result->Set(NanNew<String>("pub_reference_list"), refarr);
    }

    GTVerificationInfo_free(verification_info);
    NanReturnValue(result);
  }


  static NAN_METHOD(IsExtended)
  {
    NanScope();
    UNWRAP_ts();

    int res = GTTimestamp_isExtended(ts->timestamp);

    switch (res) {
      case GT_EXTENDED:
          NanReturnValue(NanTrue());
      case GT_NOT_EXTENDED:
          NanReturnValue(NanFalse());
      default:
          return NanThrowError(GT_getErrorString(res));
    }
  }


  // return openssl style hash alg name
  static NAN_METHOD(GetHashAlgorithm)
  {
    NanScope();
    UNWRAP_ts();

    int alg;
    int res = GTTimestamp_getAlgorithm(ts->timestamp, &alg);
    ASSERT_GT_ERROR(res);
    NanReturnValue(hash_algorithm_name_as_String(alg));
  }

  static NAN_METHOD(GetRegisteredTime)
  {
    NanScope();
    UNWRAP_ts();

    GTVerificationInfo *verification_info = NULL;
    int res = GTTimestamp_verify(ts->timestamp, 0, &verification_info);
    ASSERT_GT_ERROR(res);

    if (verification_info->verification_errors != GT_NO_FAILURES) {
      GTVerificationInfo_free(verification_info);
      return NanThrowError("TimeSignature verification error");
    }

    double result = verification_info->implicit_data->registered_time;
    GTVerificationInfo_free(verification_info);
    NanReturnValue(NODE_UNIXTIME_V8(result));
  }

    // ts.compareHash(binary hash in Buffer, algo)  -> bit flag
  static NAN_METHOD(CompareHash)
  {
    NanScope();
    UNWRAP_ts();

    if (args.Length() < 1 || args.Length() > 2) {
      return NanThrowTypeError("Wrong number of parameters");
    }
    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    if (args.Length() == 2 && !args[1]->IsString()) {
      return NanThrowTypeError("Optional 2nd argument must be hash type as string");
    }
    ssize_t len = DecodeBytes(args[0], BINARY);
    ASSERT_IS_POSITIVE(len);

    int hashalg_gt_id = 1;
    if (args.Length() == 2)
      hashalg_gt_id = getAlgoID(*String::Utf8Value(args[1]->ToString()));

    if (hashalg_gt_id < 0) {
      return NanThrowError("Unsupported hash algorithm");
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

    ASSERT_GT_ERROR(res);
    NanReturnValue(NanNew<Integer>(GT_DOCUMENT_HASH_CHECKED));
  }


    // ts.checkPublication(pub. file content in Buffer) -> true/exception
  static NAN_METHOD(CheckPublication)
  {
    NanScope();
    UNWRAP_ts();

    ASSERT_IS_N_ARGS(1);
    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    ssize_t len = DecodeBytes(args[0], BINARY);
    ASSERT_IS_POSITIVE(len);

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
    ASSERT_GT_ERROR(res);

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
        ASSERT_GT_ERROR(res);
      }

      if (verification_info->verification_errors != GT_NO_FAILURES) {
        GTVerificationInfo_free(verification_info);
        GTPublicationsFile_free(pub);
        return NanThrowError("TimeSignature verification error");
      }

      GT_Time_t64 history_id = verification_info->implicit_data->registered_time;
      GTVerificationInfo_free(verification_info);
      res = GTTimestamp_checkPublicKey(ts->timestamp, history_id, pub);
    }
    else
    {
      GTPublicationsFile_free(pub);
      ASSERT_GT_ERROR(ext);
    }

    GTPublicationsFile_free(pub);
    ASSERT_GT_ERROR(res);
    NanReturnValue(NanNew<Integer>(GT_PUBLICATION_CHECKED));
  }


  static NAN_METHOD(GetSignerName)
  {
    NanScope();
    UNWRAP_ts();

    GTVerificationInfo *verification_info = NULL;
    int res = GTTimestamp_verify(ts->timestamp, 0, &verification_info);
    ASSERT_GT_ERROR(res);

    if (verification_info->verification_errors != GT_NO_FAILURES) {
      GTVerificationInfo_free(verification_info);
      return NanThrowError("TimeSignature verification error");
    }
    Local<String> result = NanNew<String>(
          (verification_info->implicit_data->location_name != NULL) ?
            verification_info->implicit_data->location_name :
            "");
    GTVerificationInfo_free(verification_info);
    NanReturnValue(result);
  }

  // returns DER encoded ts token
  static NAN_METHOD(GetContent)
  {
    NanScope();
    UNWRAP_ts();

    unsigned char *data;
    size_t data_length;
    int res = GTTimestamp_getDEREncoded(ts->timestamp, &data, &data_length);
    ASSERT_GT_ERROR(res);

    Local<Object> result = NanNewBufferHandle((char *)data, data_length);
    GT_free(data);
    NanReturnValue(result);
  }

  // Buffer = composeExtendingRequest()
  static NAN_METHOD(ComposeExtendingRequest)
  {
    NanScope();
    UNWRAP_ts();

    unsigned char *request = NULL;
    size_t request_length;

    int res = GTTimestamp_prepareExtensionRequest(ts->timestamp, &request, &request_length);
    ASSERT_GT_ERROR(res);

    Local<Object> result = NanNewBufferHandle((char *)request, request_length);
    GT_free(request);
    NanReturnValue(result);
  }

    // ts.extend(extending response)
    // returns true or throws an exception
  static NAN_METHOD(Extend)
  {
    NanScope();
    UNWRAP_ts();

    ASSERT_IS_N_ARGS(1);
    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    ssize_t len = DecodeBytes(args[0], BINARY);
    ASSERT_IS_POSITIVE(len);

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
      NanReturnValue(NanNew<Integer>(res));

    ASSERT_GT_ERROR(res);

    GTTimestamp_free(ts->timestamp);
    ts->timestamp = new_ts;

    NanReturnValue(NanTrue());
  }


  static NAN_METHOD(IsEarlierThan)
  {
    NanScope();
    UNWRAP_ts();

    if (!TimeSignature::HasInstance(args[0])) {
      return NanThrowTypeError("First argument needs to be a TimeSignature");
    }
    TimeSignature *ts2 = ObjectWrap::Unwrap<TimeSignature>(args[0]->ToObject());
    int res = GTTimestamp_isEarlierThan(ts->timestamp, ts2->timestamp);
    switch (res) {
      case GT_EARLIER:
          NanReturnValue(NanTrue());
      case GT_NOT_EARLIER:
          NanReturnValue(NanFalse());
      default:
          return NanThrowError(GT_getErrorString(res));
    }
  }


  // 'static class methods' below: ----------------

  //   req = TimeSignature.composeRequest(hash);
  // binary string will be represented as utf8, needs DecodeBytes/DecodeWrite. \0 is ok.
  // arg: binary hash as a Buffer; hashing or interaction of Hash object should be done in JS layer
  // second optional arg: hash algorithm name as openssl style string.
  static NAN_METHOD(ComposeRequest)
  {
    NanScope();

    if (args.Length() < 1 || args.Length() > 2) {
      return NanThrowTypeError("Wrong number of arguments");
    }
    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    if (args.Length() == 2 && !args[1]->IsString()) {
      return NanThrowTypeError("Optional 2nd argument must be hash algorithm name as string");
    }
    ssize_t len = DecodeBytes(args[0], BINARY);
    ASSERT_IS_POSITIVE(len);

    int hashalg_gt_id = 1;
    if (args.Length() == 2)
      hashalg_gt_id = getAlgoID(*String::Utf8Value(args[1]->ToString()));
    if (hashalg_gt_id < 0) {
      return NanThrowTypeError("Unsupported hash algorithm");
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
    ASSERT_GT_ERROR(res);

    Local<Object> result = NanNewBufferHandle((char *)request, request_length);
    GT_free(request);
    NanReturnValue(result);
  }


    // input: raw timestamper response in Buffer, output - DER token to be fed to constructor
  static NAN_METHOD(ProcessResponse)
  {
    NanScope();

    ASSERT_IS_N_ARGS(1);
    ASSERT_IS_STRING_OR_BUFFER(args[0]);

    ssize_t len = DecodeBytes(args[0], BINARY);
    ASSERT_IS_POSITIVE(len);

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
    ASSERT_GT_ERROR(res);

    unsigned char *data;
    size_t data_length;
    res = GTTimestamp_getDEREncoded(timestamp, &data, &data_length);
    GTTimestamp_free(timestamp);
    ASSERT_GT_ERROR(res);

    Local<Object> result = NanNewBufferHandle((char *)data, data_length);
    GT_free(data);
    NanReturnValue(result);
  }


   // verifies and returns latest pub. date
  static NAN_METHOD(VerifyPublications)
  {
    NanScope();

    ASSERT_IS_N_ARGS(1);
    ASSERT_IS_STRING_OR_BUFFER(args[0]);
    ssize_t len = DecodeBytes(args[0], BINARY);
    ASSERT_IS_POSITIVE(len);

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
    ASSERT_GT_ERROR(res);

    GTPubFileVerificationInfo *vi;
    res = GTPublicationsFile_verify(pub,  &vi);
    if (res != GT_OK) {
      GTPublicationsFile_free(pub);
      ASSERT_GT_ERROR(res);
    }

    GTPublicationsFile_free(pub);
    double result = vi->last_publication_time;
    GTPubFileVerificationInfo_free(vi);

    NanReturnValue(NODE_UNIXTIME_V8(result));

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

  static bool HasInstance(Handle<Value> val) {
    if (!val->IsObject()) return false;
    Local<Object> obj = val->ToObject();
    return NanHasInstance(constructor_template, obj);
  }
};


Persistent<FunctionTemplate> TimeSignature::constructor_template;

extern "C" {
  void init (Handle<Object> target)
  {
    int res;
    res = GT_init();
    if (res != GT_OK) {
      NanThrowError(
            String::Concat(NanNew<String>("Error initializing Guardtime C SDK: "),
                           NanNew<String>(GT_getErrorString(res))));
      return;
    }
    TimeSignature::Init(target);

    // If system certificate stores not detected then use Node's root certificates to
    // validate signature on publications file.
    // If libgt is preinstalled then assume that it is already properly configured.
#if !(defined OPENSSL_CA_FILE || defined OPENSSL_CA_DIR || defined PREINSTALLED_LIBGT)
    for (int i = 0; root_certs[i]; i++) {
      res = GTTruststore_addCert(root_certs[i]);
      if ((res) != GT_OK) {
        NanThrowError(GT_getErrorString(res));
        return;
      }
    }
#endif
  }

  NODE_MODULE(timesignature, init);
}
