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
 * Check if a given object implements the SystemWriteMfaMethodTotpNameRequest interface.
 */
export function instanceOfSystemWriteMfaMethodTotpNameRequest(value) {
    return true;
}
export function SystemWriteMfaMethodTotpNameRequestFromJSON(json) {
    return SystemWriteMfaMethodTotpNameRequestFromJSONTyped(json, false);
}
export function SystemWriteMfaMethodTotpNameRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'algorithm': json['algorithm'] == null ? undefined : json['algorithm'],
        'digits': json['digits'] == null ? undefined : json['digits'],
        'issuer': json['issuer'] == null ? undefined : json['issuer'],
        'keySize': json['key_size'] == null ? undefined : json['key_size'],
        'maxValidationAttempts': json['max_validation_attempts'] == null ? undefined : json['max_validation_attempts'],
        'period': json['period'] == null ? undefined : json['period'],
        'qrSize': json['qr_size'] == null ? undefined : json['qr_size'],
        'skew': json['skew'] == null ? undefined : json['skew'],
    };
}
export function SystemWriteMfaMethodTotpNameRequestToJSON(json) {
    return SystemWriteMfaMethodTotpNameRequestToJSONTyped(json, false);
}
export function SystemWriteMfaMethodTotpNameRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'algorithm': value['algorithm'],
        'digits': value['digits'],
        'issuer': value['issuer'],
        'key_size': value['keySize'],
        'max_validation_attempts': value['maxValidationAttempts'],
        'period': value['period'],
        'qr_size': value['qrSize'],
        'skew': value['skew'],
    };
}
