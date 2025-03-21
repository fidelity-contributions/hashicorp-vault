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
/**
 * Check if a given object implements the SshListRolesByIpRequest interface.
 */
export function instanceOfSshListRolesByIpRequest(value) {
    return true;
}
export function SshListRolesByIpRequestFromJSON(json) {
    return SshListRolesByIpRequestFromJSONTyped(json, false);
}
export function SshListRolesByIpRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'ip': json['ip'] == null ? undefined : json['ip'],
    };
}
export function SshListRolesByIpRequestToJSON(json) {
    return SshListRolesByIpRequestToJSONTyped(json, false);
}
export function SshListRolesByIpRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'ip': value['ip'],
    };
}
