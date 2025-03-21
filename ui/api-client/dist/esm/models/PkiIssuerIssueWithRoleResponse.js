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
 * Check if a given object implements the PkiIssuerIssueWithRoleResponse interface.
 */
export function instanceOfPkiIssuerIssueWithRoleResponse(value) {
    return true;
}
export function PkiIssuerIssueWithRoleResponseFromJSON(json) {
    return PkiIssuerIssueWithRoleResponseFromJSONTyped(json, false);
}
export function PkiIssuerIssueWithRoleResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'caChain': json['ca_chain'] == null ? undefined : json['ca_chain'],
        'certificate': json['certificate'] == null ? undefined : json['certificate'],
        'expiration': json['expiration'] == null ? undefined : json['expiration'],
        'issuingCa': json['issuing_ca'] == null ? undefined : json['issuing_ca'],
        'privateKey': json['private_key'] == null ? undefined : json['private_key'],
        'privateKeyType': json['private_key_type'] == null ? undefined : json['private_key_type'],
        'serialNumber': json['serial_number'] == null ? undefined : json['serial_number'],
    };
}
export function PkiIssuerIssueWithRoleResponseToJSON(json) {
    return PkiIssuerIssueWithRoleResponseToJSONTyped(json, false);
}
export function PkiIssuerIssueWithRoleResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'ca_chain': value['caChain'],
        'certificate': value['certificate'],
        'expiration': value['expiration'],
        'issuing_ca': value['issuingCa'],
        'private_key': value['privateKey'],
        'private_key_type': value['privateKeyType'],
        'serial_number': value['serialNumber'],
    };
}
