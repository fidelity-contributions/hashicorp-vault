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
 * Check if a given object implements the ReadWrappingPropertiesResponse interface.
 */
export function instanceOfReadWrappingPropertiesResponse(value) {
    return true;
}
export function ReadWrappingPropertiesResponseFromJSON(json) {
    return ReadWrappingPropertiesResponseFromJSONTyped(json, false);
}
export function ReadWrappingPropertiesResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'creationPath': json['creation_path'] == null ? undefined : json['creation_path'],
        'creationTime': json['creation_time'] == null ? undefined : (new Date(json['creation_time'])),
        'creationTtl': json['creation_ttl'] == null ? undefined : json['creation_ttl'],
    };
}
export function ReadWrappingPropertiesResponseToJSON(json) {
    return ReadWrappingPropertiesResponseToJSONTyped(json, false);
}
export function ReadWrappingPropertiesResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'creation_path': value['creationPath'],
        'creation_time': value['creationTime'] == null ? undefined : ((value['creationTime']).toISOString()),
        'creation_ttl': value['creationTtl'],
    };
}
