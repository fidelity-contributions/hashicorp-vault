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
 * Check if a given object implements the UiHeadersConfigureRequest interface.
 */
export function instanceOfUiHeadersConfigureRequest(value) {
    return true;
}
export function UiHeadersConfigureRequestFromJSON(json) {
    return UiHeadersConfigureRequestFromJSONTyped(json, false);
}
export function UiHeadersConfigureRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'multivalue': json['multivalue'] == null ? undefined : json['multivalue'],
        'values': json['values'] == null ? undefined : json['values'],
    };
}
export function UiHeadersConfigureRequestToJSON(json) {
    return UiHeadersConfigureRequestToJSONTyped(json, false);
}
export function UiHeadersConfigureRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'multivalue': value['multivalue'],
        'values': value['values'],
    };
}
