"use strict";
/* tslint:disable */
/* eslint-disable */
/**
 * HashiCorp Vault API
 * HTTP API that gives you full access to Vault. All API routes are prefixed with `/v1/`.
 *
 * The version of the OpenAPI document: 1.20.0
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.instanceOfPkiReadCertRawPemResponse = instanceOfPkiReadCertRawPemResponse;
exports.PkiReadCertRawPemResponseFromJSON = PkiReadCertRawPemResponseFromJSON;
exports.PkiReadCertRawPemResponseFromJSONTyped = PkiReadCertRawPemResponseFromJSONTyped;
exports.PkiReadCertRawPemResponseToJSON = PkiReadCertRawPemResponseToJSON;
exports.PkiReadCertRawPemResponseToJSONTyped = PkiReadCertRawPemResponseToJSONTyped;
/**
 * Check if a given object implements the PkiReadCertRawPemResponse interface.
 */
function instanceOfPkiReadCertRawPemResponse(value) {
    return true;
}
function PkiReadCertRawPemResponseFromJSON(json) {
    return PkiReadCertRawPemResponseFromJSONTyped(json, false);
}
function PkiReadCertRawPemResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'caChain': json['ca_chain'] == null ? undefined : json['ca_chain'],
        'certificate': json['certificate'] == null ? undefined : json['certificate'],
        'issuerId': json['issuer_id'] == null ? undefined : json['issuer_id'],
        'revocationTime': json['revocation_time'] == null ? undefined : json['revocation_time'],
        'revocationTimeRfc3339': json['revocation_time_rfc3339'] == null ? undefined : json['revocation_time_rfc3339'],
    };
}
function PkiReadCertRawPemResponseToJSON(json) {
    return PkiReadCertRawPemResponseToJSONTyped(json, false);
}
function PkiReadCertRawPemResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'ca_chain': value['caChain'],
        'certificate': value['certificate'],
        'issuer_id': value['issuerId'],
        'revocation_time': value['revocationTime'],
        'revocation_time_rfc3339': value['revocationTimeRfc3339'],
    };
}
