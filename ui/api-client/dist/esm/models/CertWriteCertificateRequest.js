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
 * Check if a given object implements the CertWriteCertificateRequest interface.
 */
export function instanceOfCertWriteCertificateRequest(value) {
    return true;
}
export function CertWriteCertificateRequestFromJSON(json) {
    return CertWriteCertificateRequestFromJSONTyped(json, false);
}
export function CertWriteCertificateRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'allowedCommonNames': json['allowed_common_names'] == null ? undefined : json['allowed_common_names'],
        'allowedDnsSans': json['allowed_dns_sans'] == null ? undefined : json['allowed_dns_sans'],
        'allowedEmailSans': json['allowed_email_sans'] == null ? undefined : json['allowed_email_sans'],
        'allowedMetadataExtensions': json['allowed_metadata_extensions'] == null ? undefined : json['allowed_metadata_extensions'],
        'allowedNames': json['allowed_names'] == null ? undefined : json['allowed_names'],
        'allowedOrganizationalUnits': json['allowed_organizational_units'] == null ? undefined : json['allowed_organizational_units'],
        'allowedUriSans': json['allowed_uri_sans'] == null ? undefined : json['allowed_uri_sans'],
        'boundCidrs': json['bound_cidrs'] == null ? undefined : json['bound_cidrs'],
        'certificate': json['certificate'] == null ? undefined : json['certificate'],
        'displayName': json['display_name'] == null ? undefined : json['display_name'],
        'lease': json['lease'] == null ? undefined : json['lease'],
        'maxTtl': json['max_ttl'] == null ? undefined : json['max_ttl'],
        'ocspCaCertificates': json['ocsp_ca_certificates'] == null ? undefined : json['ocsp_ca_certificates'],
        'ocspEnabled': json['ocsp_enabled'] == null ? undefined : json['ocsp_enabled'],
        'ocspFailOpen': json['ocsp_fail_open'] == null ? undefined : json['ocsp_fail_open'],
        'ocspMaxRetries': json['ocsp_max_retries'] == null ? undefined : json['ocsp_max_retries'],
        'ocspQueryAllServers': json['ocsp_query_all_servers'] == null ? undefined : json['ocsp_query_all_servers'],
        'ocspServersOverride': json['ocsp_servers_override'] == null ? undefined : json['ocsp_servers_override'],
        'ocspThisUpdateMaxAge': json['ocsp_this_update_max_age'] == null ? undefined : json['ocsp_this_update_max_age'],
        'period': json['period'] == null ? undefined : json['period'],
        'policies': json['policies'] == null ? undefined : json['policies'],
        'requiredExtensions': json['required_extensions'] == null ? undefined : json['required_extensions'],
        'tokenBoundCidrs': json['token_bound_cidrs'] == null ? undefined : json['token_bound_cidrs'],
        'tokenExplicitMaxTtl': json['token_explicit_max_ttl'] == null ? undefined : json['token_explicit_max_ttl'],
        'tokenMaxTtl': json['token_max_ttl'] == null ? undefined : json['token_max_ttl'],
        'tokenNoDefaultPolicy': json['token_no_default_policy'] == null ? undefined : json['token_no_default_policy'],
        'tokenNumUses': json['token_num_uses'] == null ? undefined : json['token_num_uses'],
        'tokenPeriod': json['token_period'] == null ? undefined : json['token_period'],
        'tokenPolicies': json['token_policies'] == null ? undefined : json['token_policies'],
        'tokenTtl': json['token_ttl'] == null ? undefined : json['token_ttl'],
        'tokenType': json['token_type'] == null ? undefined : json['token_type'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
    };
}
export function CertWriteCertificateRequestToJSON(json) {
    return CertWriteCertificateRequestToJSONTyped(json, false);
}
export function CertWriteCertificateRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'allowed_common_names': value['allowedCommonNames'],
        'allowed_dns_sans': value['allowedDnsSans'],
        'allowed_email_sans': value['allowedEmailSans'],
        'allowed_metadata_extensions': value['allowedMetadataExtensions'],
        'allowed_names': value['allowedNames'],
        'allowed_organizational_units': value['allowedOrganizationalUnits'],
        'allowed_uri_sans': value['allowedUriSans'],
        'bound_cidrs': value['boundCidrs'],
        'certificate': value['certificate'],
        'display_name': value['displayName'],
        'lease': value['lease'],
        'max_ttl': value['maxTtl'],
        'ocsp_ca_certificates': value['ocspCaCertificates'],
        'ocsp_enabled': value['ocspEnabled'],
        'ocsp_fail_open': value['ocspFailOpen'],
        'ocsp_max_retries': value['ocspMaxRetries'],
        'ocsp_query_all_servers': value['ocspQueryAllServers'],
        'ocsp_servers_override': value['ocspServersOverride'],
        'ocsp_this_update_max_age': value['ocspThisUpdateMaxAge'],
        'period': value['period'],
        'policies': value['policies'],
        'required_extensions': value['requiredExtensions'],
        'token_bound_cidrs': value['tokenBoundCidrs'],
        'token_explicit_max_ttl': value['tokenExplicitMaxTtl'],
        'token_max_ttl': value['tokenMaxTtl'],
        'token_no_default_policy': value['tokenNoDefaultPolicy'],
        'token_num_uses': value['tokenNumUses'],
        'token_period': value['tokenPeriod'],
        'token_policies': value['tokenPolicies'],
        'token_ttl': value['tokenTtl'],
        'token_type': value['tokenType'],
        'ttl': value['ttl'],
    };
}
