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
exports.instanceOfKvV2PatchResponse = instanceOfKvV2PatchResponse;
exports.KvV2PatchResponseFromJSON = KvV2PatchResponseFromJSON;
exports.KvV2PatchResponseFromJSONTyped = KvV2PatchResponseFromJSONTyped;
exports.KvV2PatchResponseToJSON = KvV2PatchResponseToJSON;
exports.KvV2PatchResponseToJSONTyped = KvV2PatchResponseToJSONTyped;
/**
 * Check if a given object implements the KvV2PatchResponse interface.
 */
function instanceOfKvV2PatchResponse(value) {
    return true;
}
function KvV2PatchResponseFromJSON(json) {
    return KvV2PatchResponseFromJSONTyped(json, false);
}
function KvV2PatchResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'createdTime': json['created_time'] == null ? undefined : (new Date(json['created_time'])),
        'customMetadata': json['custom_metadata'] == null ? undefined : json['custom_metadata'],
        'deletionTime': json['deletion_time'] == null ? undefined : json['deletion_time'],
        'destroyed': json['destroyed'] == null ? undefined : json['destroyed'],
        'version': json['version'] == null ? undefined : json['version'],
    };
}
function KvV2PatchResponseToJSON(json) {
    return KvV2PatchResponseToJSONTyped(json, false);
}
function KvV2PatchResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'created_time': value['createdTime'] == null ? undefined : ((value['createdTime']).toISOString()),
        'custom_metadata': value['customMetadata'],
        'deletion_time': value['deletionTime'],
        'destroyed': value['destroyed'],
        'version': value['version'],
    };
}
