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
exports.PkiRootSignIntermediateRequestPrivateKeyFormatEnum = exports.PkiRootSignIntermediateRequestFormatEnum = void 0;
exports.instanceOfPkiRootSignIntermediateRequest = instanceOfPkiRootSignIntermediateRequest;
exports.PkiRootSignIntermediateRequestFromJSON = PkiRootSignIntermediateRequestFromJSON;
exports.PkiRootSignIntermediateRequestFromJSONTyped = PkiRootSignIntermediateRequestFromJSONTyped;
exports.PkiRootSignIntermediateRequestToJSON = PkiRootSignIntermediateRequestToJSON;
exports.PkiRootSignIntermediateRequestToJSONTyped = PkiRootSignIntermediateRequestToJSONTyped;
/**
* @export
* @enum {string}
*/
var PkiRootSignIntermediateRequestFormatEnum;
(function (PkiRootSignIntermediateRequestFormatEnum) {
    PkiRootSignIntermediateRequestFormatEnum["PEM"] = "pem";
    PkiRootSignIntermediateRequestFormatEnum["DER"] = "der";
    PkiRootSignIntermediateRequestFormatEnum["PEM_BUNDLE"] = "pem_bundle";
})(PkiRootSignIntermediateRequestFormatEnum || (exports.PkiRootSignIntermediateRequestFormatEnum = PkiRootSignIntermediateRequestFormatEnum = {}));
/**
* @export
* @enum {string}
*/
var PkiRootSignIntermediateRequestPrivateKeyFormatEnum;
(function (PkiRootSignIntermediateRequestPrivateKeyFormatEnum) {
    PkiRootSignIntermediateRequestPrivateKeyFormatEnum["EMPTY"] = "";
    PkiRootSignIntermediateRequestPrivateKeyFormatEnum["DER"] = "der";
    PkiRootSignIntermediateRequestPrivateKeyFormatEnum["PEM"] = "pem";
    PkiRootSignIntermediateRequestPrivateKeyFormatEnum["PKCS8"] = "pkcs8";
})(PkiRootSignIntermediateRequestPrivateKeyFormatEnum || (exports.PkiRootSignIntermediateRequestPrivateKeyFormatEnum = PkiRootSignIntermediateRequestPrivateKeyFormatEnum = {}));
/**
 * Check if a given object implements the PkiRootSignIntermediateRequest interface.
 */
function instanceOfPkiRootSignIntermediateRequest(value) {
    return true;
}
function PkiRootSignIntermediateRequestFromJSON(json) {
    return PkiRootSignIntermediateRequestFromJSONTyped(json, false);
}
function PkiRootSignIntermediateRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'altNames': json['alt_names'] == null ? undefined : json['alt_names'],
        'commonName': json['common_name'] == null ? undefined : json['common_name'],
        'country': json['country'] == null ? undefined : json['country'],
        'csr': json['csr'] == null ? undefined : json['csr'],
        'enforceLeafNotAfterBehavior': json['enforce_leaf_not_after_behavior'] == null ? undefined : json['enforce_leaf_not_after_behavior'],
        'excludeCnFromSans': json['exclude_cn_from_sans'] == null ? undefined : json['exclude_cn_from_sans'],
        'excludedDnsDomains': json['excluded_dns_domains'] == null ? undefined : json['excluded_dns_domains'],
        'excludedEmailAddresses': json['excluded_email_addresses'] == null ? undefined : json['excluded_email_addresses'],
        'excludedIpRanges': json['excluded_ip_ranges'] == null ? undefined : json['excluded_ip_ranges'],
        'excludedUriDomains': json['excluded_uri_domains'] == null ? undefined : json['excluded_uri_domains'],
        'format': json['format'] == null ? undefined : json['format'],
        'ipSans': json['ip_sans'] == null ? undefined : json['ip_sans'],
        'issuerName': json['issuer_name'] == null ? undefined : json['issuer_name'],
        'issuerRef': json['issuer_ref'] == null ? undefined : json['issuer_ref'],
        'keyUsage': json['key_usage'] == null ? undefined : json['key_usage'],
        'locality': json['locality'] == null ? undefined : json['locality'],
        'maxPathLength': json['max_path_length'] == null ? undefined : json['max_path_length'],
        'notAfter': json['not_after'] == null ? undefined : json['not_after'],
        'notBeforeDuration': json['not_before_duration'] == null ? undefined : json['not_before_duration'],
        'organization': json['organization'] == null ? undefined : json['organization'],
        'otherSans': json['other_sans'] == null ? undefined : json['other_sans'],
        'ou': json['ou'] == null ? undefined : json['ou'],
        'permittedDnsDomains': json['permitted_dns_domains'] == null ? undefined : json['permitted_dns_domains'],
        'permittedEmailAddresses': json['permitted_email_addresses'] == null ? undefined : json['permitted_email_addresses'],
        'permittedIpRanges': json['permitted_ip_ranges'] == null ? undefined : json['permitted_ip_ranges'],
        'permittedUriDomains': json['permitted_uri_domains'] == null ? undefined : json['permitted_uri_domains'],
        'postalCode': json['postal_code'] == null ? undefined : json['postal_code'],
        'privateKeyFormat': json['private_key_format'] == null ? undefined : json['private_key_format'],
        'province': json['province'] == null ? undefined : json['province'],
        'serialNumber': json['serial_number'] == null ? undefined : json['serial_number'],
        'signatureBits': json['signature_bits'] == null ? undefined : json['signature_bits'],
        'skid': json['skid'] == null ? undefined : json['skid'],
        'streetAddress': json['street_address'] == null ? undefined : json['street_address'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
        'uriSans': json['uri_sans'] == null ? undefined : json['uri_sans'],
        'useCsrValues': json['use_csr_values'] == null ? undefined : json['use_csr_values'],
        'usePss': json['use_pss'] == null ? undefined : json['use_pss'],
    };
}
function PkiRootSignIntermediateRequestToJSON(json) {
    return PkiRootSignIntermediateRequestToJSONTyped(json, false);
}
function PkiRootSignIntermediateRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'alt_names': value['altNames'],
        'common_name': value['commonName'],
        'country': value['country'],
        'csr': value['csr'],
        'enforce_leaf_not_after_behavior': value['enforceLeafNotAfterBehavior'],
        'exclude_cn_from_sans': value['excludeCnFromSans'],
        'excluded_dns_domains': value['excludedDnsDomains'],
        'excluded_email_addresses': value['excludedEmailAddresses'],
        'excluded_ip_ranges': value['excludedIpRanges'],
        'excluded_uri_domains': value['excludedUriDomains'],
        'format': value['format'],
        'ip_sans': value['ipSans'],
        'issuer_name': value['issuerName'],
        'issuer_ref': value['issuerRef'],
        'key_usage': value['keyUsage'],
        'locality': value['locality'],
        'max_path_length': value['maxPathLength'],
        'not_after': value['notAfter'],
        'not_before_duration': value['notBeforeDuration'],
        'organization': value['organization'],
        'other_sans': value['otherSans'],
        'ou': value['ou'],
        'permitted_dns_domains': value['permittedDnsDomains'],
        'permitted_email_addresses': value['permittedEmailAddresses'],
        'permitted_ip_ranges': value['permittedIpRanges'],
        'permitted_uri_domains': value['permittedUriDomains'],
        'postal_code': value['postalCode'],
        'private_key_format': value['privateKeyFormat'],
        'province': value['province'],
        'serial_number': value['serialNumber'],
        'signature_bits': value['signatureBits'],
        'skid': value['skid'],
        'street_address': value['streetAddress'],
        'ttl': value['ttl'],
        'uri_sans': value['uriSans'],
        'use_csr_values': value['useCsrValues'],
        'use_pss': value['usePss'],
    };
}
