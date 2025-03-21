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
exports.instanceOfPkiIssuersImportCertResponse = instanceOfPkiIssuersImportCertResponse;
exports.PkiIssuersImportCertResponseFromJSON = PkiIssuersImportCertResponseFromJSON;
exports.PkiIssuersImportCertResponseFromJSONTyped = PkiIssuersImportCertResponseFromJSONTyped;
exports.PkiIssuersImportCertResponseToJSON = PkiIssuersImportCertResponseToJSON;
exports.PkiIssuersImportCertResponseToJSONTyped = PkiIssuersImportCertResponseToJSONTyped;
/**
 * Check if a given object implements the PkiIssuersImportCertResponse interface.
 */
function instanceOfPkiIssuersImportCertResponse(value) {
    return true;
}
function PkiIssuersImportCertResponseFromJSON(json) {
    return PkiIssuersImportCertResponseFromJSONTyped(json, false);
}
function PkiIssuersImportCertResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'existingIssuers': json['existing_issuers'] == null ? undefined : json['existing_issuers'],
        'existingKeys': json['existing_keys'] == null ? undefined : json['existing_keys'],
        'importedIssuers': json['imported_issuers'] == null ? undefined : json['imported_issuers'],
        'importedKeys': json['imported_keys'] == null ? undefined : json['imported_keys'],
        'mapping': json['mapping'] == null ? undefined : json['mapping'],
    };
}
function PkiIssuersImportCertResponseToJSON(json) {
    return PkiIssuersImportCertResponseToJSONTyped(json, false);
}
function PkiIssuersImportCertResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'existing_issuers': value['existingIssuers'],
        'existing_keys': value['existingKeys'],
        'imported_issuers': value['importedIssuers'],
        'imported_keys': value['importedKeys'],
        'mapping': value['mapping'],
    };
}
