/* Typed JWT bindings. JSON objects/arrays are serialized through tjson;
 * Tink retains responsibility for JWT wire parsing and cryptography.
 * SPDX-License-Identifier: MIT */
#include <tink/jwt/jwt_mac.h>
#include <cmath>

static int JwtError(Tcl_Interp *interp, const char *kind, const char *message) {
    Tcl_SetObjResult(interp, Tcl_NewStringObj(message, -1));
    Tcl_SetErrorCode(interp, "TINK", "JWT", kind, nullptr);
    return TCL_ERROR;
}
static std::string JwtString(Tcl_Obj *obj) {
    Tcl_Size len;
    const char *s = Tcl_GetStringFromObj(obj, &len);
    return std::string(s, len);
}
static int JwtJson(Tcl_Interp *interp, Tcl_Obj *typed, std::string *json) {
    if (!Tcl_PkgRequire(interp, "tjson", "1.0.28", 0)) return TCL_ERROR;
    Tcl_Obj *args[] = {Tcl_NewStringObj("::tjson::typed_to_json", -1), typed};
    for (auto obj : args) Tcl_IncrRefCount(obj);
    int status = Tcl_EvalObjv(interp, 2, args, TCL_EVAL_GLOBAL);
    for (auto obj : args) Tcl_DecrRefCount(obj);
    if (status == TCL_OK) *json = JwtString(Tcl_GetObjResult(interp));
    return status;
}
static int JwtSignCmd(ClientData macMode, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc < 3 || objc > 4) {Tcl_WrongNumArgs(interp, 1, objv, "keyset typed_claims ?type?"); return TCL_ERROR;}
    auto key = tink_GetInternalFromKeysetName(interp, Tcl_GetString(objv[1]));
    if (!key) return JwtError(interp, "KEY", "keyset handle not found");
    Tcl_Size count; Tcl_Obj **parts;
    if (Tcl_ListObjGetElements(interp, objv[2], &count, &parts) != TCL_OK || count != 2 || JwtString(parts[0]) != "M")
        return JwtError(interp, "CLAIMS", "claims must be a tjson typed object");
    RawJwtBuilder builder;
    if (objc == 4 && !JwtString(objv[3]).empty()) builder.SetTypeHeader(JwtString(objv[3]));
    Tcl_DictSearch search; Tcl_Obj *name, *typed; int done;
    if (Tcl_DictObjFirst(interp, parts[1], &search, &name, &typed, &done) != TCL_OK) return TCL_ERROR;
    int status = TCL_OK;
    for (; !done; Tcl_DictObjNext(&search, &name, &typed, &done)) {
        Tcl_Size n; Tcl_Obj **v;
        if (Tcl_ListObjGetElements(interp, typed, &n, &v) != TCL_OK || n != 2) {status = TCL_ERROR; break;}
        std::string field = JwtString(name), type = JwtString(v[0]);
        if (field == "exp" || field == "iat" || field == "nbf") {
            Tcl_WideInt value;
            if (type != "N" || Tcl_GetWideIntFromObj(interp, v[1], &value) != TCL_OK || value < 0 || value > 253402300799LL) {status = TCL_ERROR; break;}
            if (field == "exp") builder.SetExpiration(absl::FromUnixSeconds(value));
            else if (field == "iat") builder.SetIssuedAt(absl::FromUnixSeconds(value));
            else builder.SetNotBefore(absl::FromUnixSeconds(value));
        } else if (field == "aud") {
            if (type == "S") builder.AddAudience(JwtString(v[1]));
            else if (type == "L") {
                Tcl_Size len; Tcl_Obj **audiences;
                if (Tcl_ListObjGetElements(interp, v[1], &len, &audiences) != TCL_OK || len == 0) {status = TCL_ERROR; break;}
                for (Tcl_Size i = 0; i < len; i++) {
                    Tcl_Size nn; Tcl_Obj **av;
                    if (Tcl_ListObjGetElements(interp, audiences[i], &nn, &av) != TCL_OK || nn != 2 || JwtString(av[0]) != "S") {status = TCL_ERROR; break;}
                    builder.AddAudience(JwtString(av[1]));
                }
                if (status != TCL_OK) break;
            } else {status = TCL_ERROR; break;}
        } else if (field == "iss" || field == "sub" || field == "jti") {
            if (type != "S") {status = TCL_ERROR; break;}
            if (field == "iss") builder.SetIssuer(JwtString(v[1]));
            else if (field == "sub") builder.SetSubject(JwtString(v[1]));
            else builder.SetJwtId(JwtString(v[1]));
        } else if (type == "S") builder.AddStringClaim(field, JwtString(v[1]));
        else if (type == "BOOL") {
            int value;
            if (Tcl_GetBooleanFromObj(interp, v[1], &value) != TCL_OK) {status = TCL_ERROR; break;}
            builder.AddBooleanClaim(field, value);
        } else if (type == "N" && JwtString(v[1]) == "null") builder.AddNullClaim(field);
        else if (type == "N") {
            double value;
            if (Tcl_GetDoubleFromObj(interp, v[1], &value) != TCL_OK || !std::isfinite(value)) {status = TCL_ERROR; break;}
            builder.AddNumberClaim(field, value);
        } else if (type == "M" || type == "L") {
            std::string json;
            if (JwtJson(interp, typed, &json) != TCL_OK) {status = TCL_ERROR; break;}
            if (type == "M") builder.AddJsonObjectClaim(field, json); else builder.AddJsonArrayClaim(field, json);
        } else {status = TCL_ERROR; break;}
    }
    Tcl_DictObjDone(&search);
    if (status != TCL_OK) return JwtError(interp, "CLAIMS", "invalid typed JWT claims");
    auto raw = builder.Build();
    if (!raw.ok()) return JwtError(interp, "CLAIMS", "invalid JWT claims or missing expiration");
    // Serialization invokes Tcl; recheck lifetime before using the native key.
    key = tink_GetInternalFromKeysetName(interp, Tcl_GetString(objv[1]));
    if (!key) return JwtError(interp, "KEY", "keyset handle not found");
    absl::StatusOr<std::string> token = absl::InvalidArgumentError("key");
    if (macMode) {
        auto primitive = key->keyset_handle->GetPrimitive<crypto::tink::JwtMac>();
        if (!primitive.ok()) return JwtError(interp, "KEY", "keyset does not support JWT MAC");
        token = (*primitive)->ComputeMacAndEncode(*raw);
    } else {
        auto primitive = key->keyset_handle->GetPrimitive<JwtPublicKeySign>();
        if (!primitive.ok()) return JwtError(interp, "KEY", "keyset does not support JWT signing");
        token = (*primitive)->SignAndEncode(*raw);
    }
    if (!token.ok()) return JwtError(interp, "SIGN", "JWT signing failed");
    Tcl_SetObjResult(interp, Tcl_NewStringObj(token->data(), token->size()));
    return TCL_OK;
}
static int JwtVerifyCmd(ClientData macMode, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 4) {Tcl_WrongNumArgs(interp, 1, objv, "keyset compact validator_dict"); return TCL_ERROR;}
    auto key = tink_GetInternalFromKeysetName(interp, Tcl_GetString(objv[1]));
    if (!key) return JwtError(interp, "KEY", "keyset handle not found");
    JwtValidatorBuilder builder;
    builder.ExpectIssuedInThePast();
    Tcl_DictSearch search; Tcl_Obj *name, *value; int done;
    if (Tcl_DictObjFirst(interp, objv[3], &search, &name, &value, &done) != TCL_OK) return TCL_ERROR;
    int status = TCL_OK;
    bool issuer = false, audience = false, type = false;
    for (; !done; Tcl_DictObjNext(&search, &name, &value, &done)) {
        std::string field = JwtString(name);
        if (field == "issuer") {builder.ExpectIssuer(JwtString(value)); issuer = true;}
        else if (field == "audience") {builder.ExpectAudience(JwtString(value)); audience = true;}
        else if (field == "type") {builder.ExpectTypeHeader(JwtString(value)); type = true;}
        else if (field == "clock_skew" || field == "now") {
            Tcl_WideInt seconds;
            if (Tcl_GetWideIntFromObj(interp, value, &seconds) != TCL_OK || seconds < 0 || (field == "clock_skew" && seconds > 300)) {status = TCL_ERROR; break;}
            if (field == "now") builder.SetFixedNow(absl::FromUnixSeconds(seconds)); else builder.SetClockSkew(absl::Seconds(seconds));
        } else {status = TCL_ERROR; break;}
    }
    Tcl_DictObjDone(&search);
    if (status != TCL_OK || !issuer || !audience) return JwtError(interp, "VALIDATOR", "issuer, audience and valid JWT options are required");
    if (!type) builder.IgnoreTypeHeader();
    auto validator = builder.Build();
    if (!validator.ok()) return JwtError(interp, "VALIDATOR", "invalid JWT validator");
    absl::StatusOr<VerifiedJwt> result = absl::InvalidArgumentError("JWT");
    if (macMode) {
        auto primitive = key->keyset_handle->GetPrimitive<crypto::tink::JwtMac>();
        if (!primitive.ok()) return JwtError(interp, "KEY", "keyset does not support JWT MAC");
        result = (*primitive)->VerifyMacAndDecode(JwtString(objv[2]), *validator);
    } else {
        auto primitive = key->keyset_handle->GetPrimitive<JwtPublicKeyVerify>();
        if (!primitive.ok()) return JwtError(interp, "KEY", "keyset does not support JWT verification");
        result = (*primitive)->VerifyAndDecode(JwtString(objv[2]), *validator);
    }
    if (!result.ok()) return JwtError(interp, "VERIFY", "JWT verification failed");
    auto json = result->GetJsonPayload();
    if (!json.ok()) return JwtError(interp, "VERIFY", "JWT payload unavailable");
    Tcl_SetObjResult(interp, Tcl_NewStringObj(json->data(), json->size()));
    return TCL_OK;
}
static int JwtImportCmd(ClientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {Tcl_WrongNumArgs(interp, 1, objv, "jwks_json"); return TCL_ERROR;}
    auto handle = JwkSetToPublicKeysetHandle(JwtString(objv[1]));
    if (!handle.ok()) return JwtError(interp, "JWK", "invalid public JWKS");
    auto internal = (tink_keyset_t *)Tcl_Alloc(sizeof(tink_keyset_t));
    internal->keyset_handle = handle->release(); internal->owner = interp;
    char name[80];
    tink_KeysetName(name);
    tink_RegisterKeysetName(name, internal);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(name, -1));
    return TCL_OK;
}
static int JwtExportCmd(ClientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 2) {Tcl_WrongNumArgs(interp, 1, objv, "keyset"); return TCL_ERROR;}
    auto key = tink_GetInternalFromKeysetName(interp, Tcl_GetString(objv[1]));
    if (!key) return JwtError(interp, "KEY", "keyset handle not found");
    auto json = JwkSetFromPublicKeysetHandle(*key->keyset_handle);
    if (!json.ok()) {
        auto pub = key->keyset_handle->GetPublicKeysetHandle();
        if (!pub.ok()) return JwtError(interp, "KEY", "keyset has no public JWT keys");
        json = JwkSetFromPublicKeysetHandle(**pub);
    }
    if (!json.ok()) return JwtError(interp, "JWK", "public JWKS export failed");
    Tcl_SetObjResult(interp, Tcl_NewStringObj(json->data(), json->size()));
    return TCL_OK;
}
