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
exports.instanceOfGenerateHashRequest = instanceOfGenerateHashRequest;
exports.GenerateHashRequestFromJSON = GenerateHashRequestFromJSON;
exports.GenerateHashRequestFromJSONTyped = GenerateHashRequestFromJSONTyped;
exports.GenerateHashRequestToJSON = GenerateHashRequestToJSON;
exports.GenerateHashRequestToJSONTyped = GenerateHashRequestToJSONTyped;
/**
 * Check if a given object implements the GenerateHashRequest interface.
 */
function instanceOfGenerateHashRequest(value) {
    return true;
}
function GenerateHashRequestFromJSON(json) {
    return GenerateHashRequestFromJSONTyped(json, false);
}
function GenerateHashRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'algorithm': json['algorithm'] == null ? undefined : json['algorithm'],
        'format': json['format'] == null ? undefined : json['format'],
        'input': json['input'] == null ? undefined : json['input'],
    };
}
function GenerateHashRequestToJSON(json) {
    return GenerateHashRequestToJSONTyped(json, false);
}
function GenerateHashRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'algorithm': value['algorithm'],
        'format': value['format'],
        'input': value['input'],
    };
}
