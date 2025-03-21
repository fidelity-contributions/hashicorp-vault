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
exports.instanceOfTokenRevokeOrphanRequest = instanceOfTokenRevokeOrphanRequest;
exports.TokenRevokeOrphanRequestFromJSON = TokenRevokeOrphanRequestFromJSON;
exports.TokenRevokeOrphanRequestFromJSONTyped = TokenRevokeOrphanRequestFromJSONTyped;
exports.TokenRevokeOrphanRequestToJSON = TokenRevokeOrphanRequestToJSON;
exports.TokenRevokeOrphanRequestToJSONTyped = TokenRevokeOrphanRequestToJSONTyped;
/**
 * Check if a given object implements the TokenRevokeOrphanRequest interface.
 */
function instanceOfTokenRevokeOrphanRequest(value) {
    return true;
}
function TokenRevokeOrphanRequestFromJSON(json) {
    return TokenRevokeOrphanRequestFromJSONTyped(json, false);
}
function TokenRevokeOrphanRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'token': json['token'] == null ? undefined : json['token'],
    };
}
function TokenRevokeOrphanRequestToJSON(json) {
    return TokenRevokeOrphanRequestToJSONTyped(json, false);
}
function TokenRevokeOrphanRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'token': value['token'],
    };
}
