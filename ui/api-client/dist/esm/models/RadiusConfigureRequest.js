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
 * Check if a given object implements the RadiusConfigureRequest interface.
 */
export function instanceOfRadiusConfigureRequest(value) {
    return true;
}
export function RadiusConfigureRequestFromJSON(json) {
    return RadiusConfigureRequestFromJSONTyped(json, false);
}
export function RadiusConfigureRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'dialTimeout': json['dial_timeout'] == null ? undefined : json['dial_timeout'],
        'host': json['host'] == null ? undefined : json['host'],
        'nasIdentifier': json['nas_identifier'] == null ? undefined : json['nas_identifier'],
        'nasPort': json['nas_port'] == null ? undefined : json['nas_port'],
        'port': json['port'] == null ? undefined : json['port'],
        'readTimeout': json['read_timeout'] == null ? undefined : json['read_timeout'],
        'secret': json['secret'] == null ? undefined : json['secret'],
        'tokenBoundCidrs': json['token_bound_cidrs'] == null ? undefined : json['token_bound_cidrs'],
        'tokenExplicitMaxTtl': json['token_explicit_max_ttl'] == null ? undefined : json['token_explicit_max_ttl'],
        'tokenMaxTtl': json['token_max_ttl'] == null ? undefined : json['token_max_ttl'],
        'tokenNoDefaultPolicy': json['token_no_default_policy'] == null ? undefined : json['token_no_default_policy'],
        'tokenNumUses': json['token_num_uses'] == null ? undefined : json['token_num_uses'],
        'tokenPeriod': json['token_period'] == null ? undefined : json['token_period'],
        'tokenPolicies': json['token_policies'] == null ? undefined : json['token_policies'],
        'tokenTtl': json['token_ttl'] == null ? undefined : json['token_ttl'],
        'tokenType': json['token_type'] == null ? undefined : json['token_type'],
        'unregisteredUserPolicies': json['unregistered_user_policies'] == null ? undefined : json['unregistered_user_policies'],
    };
}
export function RadiusConfigureRequestToJSON(json) {
    return RadiusConfigureRequestToJSONTyped(json, false);
}
export function RadiusConfigureRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'dial_timeout': value['dialTimeout'],
        'host': value['host'],
        'nas_identifier': value['nasIdentifier'],
        'nas_port': value['nasPort'],
        'port': value['port'],
        'read_timeout': value['readTimeout'],
        'secret': value['secret'],
        'token_bound_cidrs': value['tokenBoundCidrs'],
        'token_explicit_max_ttl': value['tokenExplicitMaxTtl'],
        'token_max_ttl': value['tokenMaxTtl'],
        'token_no_default_policy': value['tokenNoDefaultPolicy'],
        'token_num_uses': value['tokenNumUses'],
        'token_period': value['tokenPeriod'],
        'token_policies': value['tokenPolicies'],
        'token_ttl': value['tokenTtl'],
        'token_type': value['tokenType'],
        'unregistered_user_policies': value['unregisteredUserPolicies'],
    };
}
