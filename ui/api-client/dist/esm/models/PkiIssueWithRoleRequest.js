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
* @export
* @enum {string}
*/
export var PkiIssueWithRoleRequestFormatEnum;
(function (PkiIssueWithRoleRequestFormatEnum) {
    PkiIssueWithRoleRequestFormatEnum["PEM"] = "pem";
    PkiIssueWithRoleRequestFormatEnum["DER"] = "der";
    PkiIssueWithRoleRequestFormatEnum["PEM_BUNDLE"] = "pem_bundle";
})(PkiIssueWithRoleRequestFormatEnum || (PkiIssueWithRoleRequestFormatEnum = {}));
/**
* @export
* @enum {string}
*/
export var PkiIssueWithRoleRequestPrivateKeyFormatEnum;
(function (PkiIssueWithRoleRequestPrivateKeyFormatEnum) {
    PkiIssueWithRoleRequestPrivateKeyFormatEnum["EMPTY"] = "";
    PkiIssueWithRoleRequestPrivateKeyFormatEnum["DER"] = "der";
    PkiIssueWithRoleRequestPrivateKeyFormatEnum["PEM"] = "pem";
    PkiIssueWithRoleRequestPrivateKeyFormatEnum["PKCS8"] = "pkcs8";
})(PkiIssueWithRoleRequestPrivateKeyFormatEnum || (PkiIssueWithRoleRequestPrivateKeyFormatEnum = {}));
/**
 * Check if a given object implements the PkiIssueWithRoleRequest interface.
 */
export function instanceOfPkiIssueWithRoleRequest(value) {
    return true;
}
export function PkiIssueWithRoleRequestFromJSON(json) {
    return PkiIssueWithRoleRequestFromJSONTyped(json, false);
}
export function PkiIssueWithRoleRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'altNames': json['alt_names'] == null ? undefined : json['alt_names'],
        'certMetadata': json['cert_metadata'] == null ? undefined : json['cert_metadata'],
        'commonName': json['common_name'] == null ? undefined : json['common_name'],
        'excludeCnFromSans': json['exclude_cn_from_sans'] == null ? undefined : json['exclude_cn_from_sans'],
        'format': json['format'] == null ? undefined : json['format'],
        'ipSans': json['ip_sans'] == null ? undefined : json['ip_sans'],
        'issuerRef': json['issuer_ref'] == null ? undefined : json['issuer_ref'],
        'notAfter': json['not_after'] == null ? undefined : json['not_after'],
        'otherSans': json['other_sans'] == null ? undefined : json['other_sans'],
        'privateKeyFormat': json['private_key_format'] == null ? undefined : json['private_key_format'],
        'removeRootsFromChain': json['remove_roots_from_chain'] == null ? undefined : json['remove_roots_from_chain'],
        'serialNumber': json['serial_number'] == null ? undefined : json['serial_number'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
        'uriSans': json['uri_sans'] == null ? undefined : json['uri_sans'],
        'userIds': json['user_ids'] == null ? undefined : json['user_ids'],
    };
}
export function PkiIssueWithRoleRequestToJSON(json) {
    return PkiIssueWithRoleRequestToJSONTyped(json, false);
}
export function PkiIssueWithRoleRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'alt_names': value['altNames'],
        'cert_metadata': value['certMetadata'],
        'common_name': value['commonName'],
        'exclude_cn_from_sans': value['excludeCnFromSans'],
        'format': value['format'],
        'ip_sans': value['ipSans'],
        'issuer_ref': value['issuerRef'],
        'not_after': value['notAfter'],
        'other_sans': value['otherSans'],
        'private_key_format': value['privateKeyFormat'],
        'remove_roots_from_chain': value['removeRootsFromChain'],
        'serial_number': value['serialNumber'],
        'ttl': value['ttl'],
        'uri_sans': value['uriSans'],
        'user_ids': value['userIds'],
    };
}
