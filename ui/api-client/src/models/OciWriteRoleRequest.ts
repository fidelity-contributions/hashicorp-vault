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

import { mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface OciWriteRoleRequest
 */
export interface OciWriteRoleRequest {
    /**
     * A comma separated list of Group or Dynamic Group OCIDs that are allowed to take this role.
     * @type {Array<string>}
     * @memberof OciWriteRoleRequest
     */
    ocidList?: Array<string>;
    /**
     * Comma separated string or JSON list of CIDR blocks. If set, specifies the blocks of IP addresses which are allowed to use the generated token.
     * @type {Array<string>}
     * @memberof OciWriteRoleRequest
     */
    tokenBoundCidrs?: Array<string>;
    /**
     * If set, tokens created via this role carry an explicit maximum TTL. During renewal, the current maximum TTL values of the role and the mount are not checked for changes, and any updates to these values will have no effect on the token being renewed.
     * @type {string}
     * @memberof OciWriteRoleRequest
     */
    tokenExplicitMaxTtl?: string;
    /**
     * The maximum lifetime of the generated token
     * @type {string}
     * @memberof OciWriteRoleRequest
     */
    tokenMaxTtl?: string;
    /**
     * If true, the 'default' policy will not automatically be added to generated tokens
     * @type {boolean}
     * @memberof OciWriteRoleRequest
     */
    tokenNoDefaultPolicy?: boolean;
    /**
     * The maximum number of times a token may be used, a value of zero means unlimited
     * @type {number}
     * @memberof OciWriteRoleRequest
     */
    tokenNumUses?: number;
    /**
     * If set, tokens created via this role will have no max lifetime; instead, their renewal period will be fixed to this value. This takes an integer number of seconds, or a string duration (e.g. "24h").
     * @type {string}
     * @memberof OciWriteRoleRequest
     */
    tokenPeriod?: string;
    /**
     * Comma-separated list of policies
     * @type {Array<string>}
     * @memberof OciWriteRoleRequest
     */
    tokenPolicies?: Array<string>;
    /**
     * The initial ttl of the token to generate
     * @type {string}
     * @memberof OciWriteRoleRequest
     */
    tokenTtl?: string;
    /**
     * The type of token to generate, service or batch
     * @type {string}
     * @memberof OciWriteRoleRequest
     */
    tokenType?: string;
}

/**
 * Check if a given object implements the OciWriteRoleRequest interface.
 */
export function instanceOfOciWriteRoleRequest(value: object): value is OciWriteRoleRequest {
    return true;
}

export function OciWriteRoleRequestFromJSON(json: any): OciWriteRoleRequest {
    return OciWriteRoleRequestFromJSONTyped(json, false);
}

export function OciWriteRoleRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): OciWriteRoleRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'ocidList': json['ocid_list'] == null ? undefined : json['ocid_list'],
        'tokenBoundCidrs': json['token_bound_cidrs'] == null ? undefined : json['token_bound_cidrs'],
        'tokenExplicitMaxTtl': json['token_explicit_max_ttl'] == null ? undefined : json['token_explicit_max_ttl'],
        'tokenMaxTtl': json['token_max_ttl'] == null ? undefined : json['token_max_ttl'],
        'tokenNoDefaultPolicy': json['token_no_default_policy'] == null ? undefined : json['token_no_default_policy'],
        'tokenNumUses': json['token_num_uses'] == null ? undefined : json['token_num_uses'],
        'tokenPeriod': json['token_period'] == null ? undefined : json['token_period'],
        'tokenPolicies': json['token_policies'] == null ? undefined : json['token_policies'],
        'tokenTtl': json['token_ttl'] == null ? undefined : json['token_ttl'],
        'tokenType': json['token_type'] == null ? undefined : json['token_type'],
    };
}

export function OciWriteRoleRequestToJSON(json: any): OciWriteRoleRequest {
    return OciWriteRoleRequestToJSONTyped(json, false);
}

export function OciWriteRoleRequestToJSONTyped(value?: OciWriteRoleRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'ocid_list': value['ocidList'],
        'token_bound_cidrs': value['tokenBoundCidrs'],
        'token_explicit_max_ttl': value['tokenExplicitMaxTtl'],
        'token_max_ttl': value['tokenMaxTtl'],
        'token_no_default_policy': value['tokenNoDefaultPolicy'],
        'token_num_uses': value['tokenNumUses'],
        'token_period': value['tokenPeriod'],
        'token_policies': value['tokenPolicies'],
        'token_ttl': value['tokenTtl'],
        'token_type': value['tokenType'],
    };
}

