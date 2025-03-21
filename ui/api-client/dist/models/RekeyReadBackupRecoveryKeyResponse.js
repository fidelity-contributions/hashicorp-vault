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
exports.instanceOfRekeyReadBackupRecoveryKeyResponse = instanceOfRekeyReadBackupRecoveryKeyResponse;
exports.RekeyReadBackupRecoveryKeyResponseFromJSON = RekeyReadBackupRecoveryKeyResponseFromJSON;
exports.RekeyReadBackupRecoveryKeyResponseFromJSONTyped = RekeyReadBackupRecoveryKeyResponseFromJSONTyped;
exports.RekeyReadBackupRecoveryKeyResponseToJSON = RekeyReadBackupRecoveryKeyResponseToJSON;
exports.RekeyReadBackupRecoveryKeyResponseToJSONTyped = RekeyReadBackupRecoveryKeyResponseToJSONTyped;
/**
 * Check if a given object implements the RekeyReadBackupRecoveryKeyResponse interface.
 */
function instanceOfRekeyReadBackupRecoveryKeyResponse(value) {
    return true;
}
function RekeyReadBackupRecoveryKeyResponseFromJSON(json) {
    return RekeyReadBackupRecoveryKeyResponseFromJSONTyped(json, false);
}
function RekeyReadBackupRecoveryKeyResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'keys': json['keys'] == null ? undefined : json['keys'],
        'keysBase64': json['keys_base64'] == null ? undefined : json['keys_base64'],
        'nonce': json['nonce'] == null ? undefined : json['nonce'],
    };
}
function RekeyReadBackupRecoveryKeyResponseToJSON(json) {
    return RekeyReadBackupRecoveryKeyResponseToJSONTyped(json, false);
}
function RekeyReadBackupRecoveryKeyResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'keys': value['keys'],
        'keys_base64': value['keysBase64'],
        'nonce': value['nonce'],
    };
}
