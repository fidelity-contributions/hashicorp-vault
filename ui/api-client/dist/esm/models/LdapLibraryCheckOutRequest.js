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
 * Check if a given object implements the LdapLibraryCheckOutRequest interface.
 */
export function instanceOfLdapLibraryCheckOutRequest(value) {
    return true;
}
export function LdapLibraryCheckOutRequestFromJSON(json) {
    return LdapLibraryCheckOutRequestFromJSONTyped(json, false);
}
export function LdapLibraryCheckOutRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
    };
}
export function LdapLibraryCheckOutRequestToJSON(json) {
    return LdapLibraryCheckOutRequestToJSONTyped(json, false);
}
export function LdapLibraryCheckOutRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'ttl': value['ttl'],
    };
}
