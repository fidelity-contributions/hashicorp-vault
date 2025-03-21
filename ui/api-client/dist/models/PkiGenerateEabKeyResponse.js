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
exports.instanceOfPkiGenerateEabKeyResponse = instanceOfPkiGenerateEabKeyResponse;
exports.PkiGenerateEabKeyResponseFromJSON = PkiGenerateEabKeyResponseFromJSON;
exports.PkiGenerateEabKeyResponseFromJSONTyped = PkiGenerateEabKeyResponseFromJSONTyped;
exports.PkiGenerateEabKeyResponseToJSON = PkiGenerateEabKeyResponseToJSON;
exports.PkiGenerateEabKeyResponseToJSONTyped = PkiGenerateEabKeyResponseToJSONTyped;
/**
 * Check if a given object implements the PkiGenerateEabKeyResponse interface.
 */
function instanceOfPkiGenerateEabKeyResponse(value) {
    return true;
}
function PkiGenerateEabKeyResponseFromJSON(json) {
    return PkiGenerateEabKeyResponseFromJSONTyped(json, false);
}
function PkiGenerateEabKeyResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'acmeDirectory': json['acme_directory'] == null ? undefined : json['acme_directory'],
        'createdOn': json['created_on'] == null ? undefined : (new Date(json['created_on'])),
        'id': json['id'] == null ? undefined : json['id'],
        'key': json['key'] == null ? undefined : json['key'],
        'keyType': json['key_type'] == null ? undefined : json['key_type'],
    };
}
function PkiGenerateEabKeyResponseToJSON(json) {
    return PkiGenerateEabKeyResponseToJSONTyped(json, false);
}
function PkiGenerateEabKeyResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'acme_directory': value['acmeDirectory'],
        'created_on': value['createdOn'] == null ? undefined : ((value['createdOn']).toISOString()),
        'id': value['id'],
        'key': value['key'],
        'key_type': value['keyType'],
    };
}
