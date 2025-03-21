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
exports.instanceOfPoliciesReadAclPolicyResponse = instanceOfPoliciesReadAclPolicyResponse;
exports.PoliciesReadAclPolicyResponseFromJSON = PoliciesReadAclPolicyResponseFromJSON;
exports.PoliciesReadAclPolicyResponseFromJSONTyped = PoliciesReadAclPolicyResponseFromJSONTyped;
exports.PoliciesReadAclPolicyResponseToJSON = PoliciesReadAclPolicyResponseToJSON;
exports.PoliciesReadAclPolicyResponseToJSONTyped = PoliciesReadAclPolicyResponseToJSONTyped;
/**
 * Check if a given object implements the PoliciesReadAclPolicyResponse interface.
 */
function instanceOfPoliciesReadAclPolicyResponse(value) {
    return true;
}
function PoliciesReadAclPolicyResponseFromJSON(json) {
    return PoliciesReadAclPolicyResponseFromJSONTyped(json, false);
}
function PoliciesReadAclPolicyResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'name': json['name'] == null ? undefined : json['name'],
        'policy': json['policy'] == null ? undefined : json['policy'],
        'rules': json['rules'] == null ? undefined : json['rules'],
    };
}
function PoliciesReadAclPolicyResponseToJSON(json) {
    return PoliciesReadAclPolicyResponseToJSONTyped(json, false);
}
function PoliciesReadAclPolicyResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'name': value['name'],
        'policy': value['policy'],
        'rules': value['rules'],
    };
}
