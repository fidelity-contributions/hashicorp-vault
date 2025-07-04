"use strict";
/* tslint:disable */
/* eslint-disable */
/**
 * HashiCorp Vault API
 * HTTP API that gives you full access to Vault. All API routes are prefixed with `/v1/`.
 *
 * The version of the OpenAPI document: 1.21.0
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PkiWriteExternalPolicySignPolicyRequestFormatEnum = void 0;
exports.instanceOfPkiWriteExternalPolicySignPolicyRequest = instanceOfPkiWriteExternalPolicySignPolicyRequest;
exports.PkiWriteExternalPolicySignPolicyRequestFromJSON = PkiWriteExternalPolicySignPolicyRequestFromJSON;
exports.PkiWriteExternalPolicySignPolicyRequestFromJSONTyped = PkiWriteExternalPolicySignPolicyRequestFromJSONTyped;
exports.PkiWriteExternalPolicySignPolicyRequestToJSON = PkiWriteExternalPolicySignPolicyRequestToJSON;
exports.PkiWriteExternalPolicySignPolicyRequestToJSONTyped = PkiWriteExternalPolicySignPolicyRequestToJSONTyped;
/**
* @export
* @enum {string}
*/
var PkiWriteExternalPolicySignPolicyRequestFormatEnum;
(function (PkiWriteExternalPolicySignPolicyRequestFormatEnum) {
    PkiWriteExternalPolicySignPolicyRequestFormatEnum["PEM"] = "pem";
    PkiWriteExternalPolicySignPolicyRequestFormatEnum["DER"] = "der";
    PkiWriteExternalPolicySignPolicyRequestFormatEnum["PEM_BUNDLE"] = "pem_bundle";
})(PkiWriteExternalPolicySignPolicyRequestFormatEnum || (exports.PkiWriteExternalPolicySignPolicyRequestFormatEnum = PkiWriteExternalPolicySignPolicyRequestFormatEnum = {}));
/**
 * Check if a given object implements the PkiWriteExternalPolicySignPolicyRequest interface.
 */
function instanceOfPkiWriteExternalPolicySignPolicyRequest(value) {
    if (!('csr' in value) || value['csr'] === undefined)
        return false;
    return true;
}
function PkiWriteExternalPolicySignPolicyRequestFromJSON(json) {
    return PkiWriteExternalPolicySignPolicyRequestFromJSONTyped(json, false);
}
function PkiWriteExternalPolicySignPolicyRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return Object.assign(Object.assign({}, json), { 'csr': json['csr'], 'format': json['format'] == null ? undefined : json['format'], 'removeRootsFromChain': json['remove_roots_from_chain'] == null ? undefined : json['remove_roots_from_chain'] });
}
function PkiWriteExternalPolicySignPolicyRequestToJSON(json) {
    return PkiWriteExternalPolicySignPolicyRequestToJSONTyped(json, false);
}
function PkiWriteExternalPolicySignPolicyRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return Object.assign(Object.assign({}, value), { 'csr': value['csr'], 'format': value['format'], 'remove_roots_from_chain': value['removeRootsFromChain'] });
}
