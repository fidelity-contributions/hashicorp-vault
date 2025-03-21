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
exports.instanceOfGoogleCloudLoginRequest = instanceOfGoogleCloudLoginRequest;
exports.GoogleCloudLoginRequestFromJSON = GoogleCloudLoginRequestFromJSON;
exports.GoogleCloudLoginRequestFromJSONTyped = GoogleCloudLoginRequestFromJSONTyped;
exports.GoogleCloudLoginRequestToJSON = GoogleCloudLoginRequestToJSON;
exports.GoogleCloudLoginRequestToJSONTyped = GoogleCloudLoginRequestToJSONTyped;
/**
 * Check if a given object implements the GoogleCloudLoginRequest interface.
 */
function instanceOfGoogleCloudLoginRequest(value) {
    return true;
}
function GoogleCloudLoginRequestFromJSON(json) {
    return GoogleCloudLoginRequestFromJSONTyped(json, false);
}
function GoogleCloudLoginRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'jwt': json['jwt'] == null ? undefined : json['jwt'],
        'role': json['role'] == null ? undefined : json['role'],
    };
}
function GoogleCloudLoginRequestToJSON(json) {
    return GoogleCloudLoginRequestToJSONTyped(json, false);
}
function GoogleCloudLoginRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'jwt': value['jwt'],
        'role': value['role'],
    };
}
