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
exports.instanceOfAliasCreateRequest = instanceOfAliasCreateRequest;
exports.AliasCreateRequestFromJSON = AliasCreateRequestFromJSON;
exports.AliasCreateRequestFromJSONTyped = AliasCreateRequestFromJSONTyped;
exports.AliasCreateRequestToJSON = AliasCreateRequestToJSON;
exports.AliasCreateRequestToJSONTyped = AliasCreateRequestToJSONTyped;
/**
 * Check if a given object implements the AliasCreateRequest interface.
 */
function instanceOfAliasCreateRequest(value) {
    return true;
}
function AliasCreateRequestFromJSON(json) {
    return AliasCreateRequestFromJSONTyped(json, false);
}
function AliasCreateRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'canonicalId': json['canonical_id'] == null ? undefined : json['canonical_id'],
        'entityId': json['entity_id'] == null ? undefined : json['entity_id'],
        'id': json['id'] == null ? undefined : json['id'],
        'mountAccessor': json['mount_accessor'] == null ? undefined : json['mount_accessor'],
        'name': json['name'] == null ? undefined : json['name'],
    };
}
function AliasCreateRequestToJSON(json) {
    return AliasCreateRequestToJSONTyped(json, false);
}
function AliasCreateRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'canonical_id': value['canonicalId'],
        'entity_id': value['entityId'],
        'id': value['id'],
        'mount_accessor': value['mountAccessor'],
        'name': value['name'],
    };
}
