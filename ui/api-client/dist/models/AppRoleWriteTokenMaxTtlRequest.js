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
exports.instanceOfAppRoleWriteTokenMaxTtlRequest = instanceOfAppRoleWriteTokenMaxTtlRequest;
exports.AppRoleWriteTokenMaxTtlRequestFromJSON = AppRoleWriteTokenMaxTtlRequestFromJSON;
exports.AppRoleWriteTokenMaxTtlRequestFromJSONTyped = AppRoleWriteTokenMaxTtlRequestFromJSONTyped;
exports.AppRoleWriteTokenMaxTtlRequestToJSON = AppRoleWriteTokenMaxTtlRequestToJSON;
exports.AppRoleWriteTokenMaxTtlRequestToJSONTyped = AppRoleWriteTokenMaxTtlRequestToJSONTyped;
/**
 * Check if a given object implements the AppRoleWriteTokenMaxTtlRequest interface.
 */
function instanceOfAppRoleWriteTokenMaxTtlRequest(value) {
    return true;
}
function AppRoleWriteTokenMaxTtlRequestFromJSON(json) {
    return AppRoleWriteTokenMaxTtlRequestFromJSONTyped(json, false);
}
function AppRoleWriteTokenMaxTtlRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'tokenMaxTtl': json['token_max_ttl'] == null ? undefined : json['token_max_ttl'],
    };
}
function AppRoleWriteTokenMaxTtlRequestToJSON(json) {
    return AppRoleWriteTokenMaxTtlRequestToJSONTyped(json, false);
}
function AppRoleWriteTokenMaxTtlRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'token_max_ttl': value['tokenMaxTtl'],
    };
}
