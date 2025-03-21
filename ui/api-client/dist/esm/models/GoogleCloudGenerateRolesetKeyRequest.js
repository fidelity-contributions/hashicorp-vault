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
 * Check if a given object implements the GoogleCloudGenerateRolesetKeyRequest interface.
 */
export function instanceOfGoogleCloudGenerateRolesetKeyRequest(value) {
    return true;
}
export function GoogleCloudGenerateRolesetKeyRequestFromJSON(json) {
    return GoogleCloudGenerateRolesetKeyRequestFromJSONTyped(json, false);
}
export function GoogleCloudGenerateRolesetKeyRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'keyAlgorithm': json['key_algorithm'] == null ? undefined : json['key_algorithm'],
        'keyType': json['key_type'] == null ? undefined : json['key_type'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
    };
}
export function GoogleCloudGenerateRolesetKeyRequestToJSON(json) {
    return GoogleCloudGenerateRolesetKeyRequestToJSONTyped(json, false);
}
export function GoogleCloudGenerateRolesetKeyRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'key_algorithm': value['keyAlgorithm'],
        'key_type': value['keyType'],
        'ttl': value['ttl'],
    };
}
