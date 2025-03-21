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
 * @interface TokenCreateAgainstRoleRequest
 */
export interface TokenCreateAgainstRoleRequest {
    /**
     * Name to associate with this token
     * @type {string}
     * @memberof TokenCreateAgainstRoleRequest
     */
    displayName?: string;
    /**
     * Name of the entity alias to associate with this token
     * @type {string}
     * @memberof TokenCreateAgainstRoleRequest
     */
    entityAlias?: string;
    /**
     * Explicit Max TTL of this token
     * @type {string}
     * @memberof TokenCreateAgainstRoleRequest
     */
    explicitMaxTtl?: string;
    /**
     * Value for the token
     * @type {string}
     * @memberof TokenCreateAgainstRoleRequest
     */
    id?: string;
    /**
     * Use 'ttl' instead
     * @type {string}
     * @memberof TokenCreateAgainstRoleRequest
     * @deprecated
     */
    lease?: string;
    /**
     * Arbitrary key=value metadata to associate with the token
     * @type {object}
     * @memberof TokenCreateAgainstRoleRequest
     */
    meta?: object;
    /**
     * Do not include default policy for this token
     * @type {boolean}
     * @memberof TokenCreateAgainstRoleRequest
     */
    noDefaultPolicy?: boolean;
    /**
     * Create the token with no parent
     * @type {boolean}
     * @memberof TokenCreateAgainstRoleRequest
     */
    noParent?: boolean;
    /**
     * Max number of uses for this token
     * @type {number}
     * @memberof TokenCreateAgainstRoleRequest
     */
    numUses?: number;
    /**
     * Renew period
     * @type {string}
     * @memberof TokenCreateAgainstRoleRequest
     */
    period?: string;
    /**
     * List of policies for the token
     * @type {Array<string>}
     * @memberof TokenCreateAgainstRoleRequest
     */
    policies?: Array<string>;
    /**
     * Allow token to be renewed past its initial TTL up to system/mount maximum TTL
     * @type {boolean}
     * @memberof TokenCreateAgainstRoleRequest
     */
    renewable?: boolean;
    /**
     * Time to live for this token
     * @type {string}
     * @memberof TokenCreateAgainstRoleRequest
     */
    ttl?: string;
    /**
     * Token type
     * @type {string}
     * @memberof TokenCreateAgainstRoleRequest
     */
    type?: string;
}

/**
 * Check if a given object implements the TokenCreateAgainstRoleRequest interface.
 */
export function instanceOfTokenCreateAgainstRoleRequest(value: object): value is TokenCreateAgainstRoleRequest {
    return true;
}

export function TokenCreateAgainstRoleRequestFromJSON(json: any): TokenCreateAgainstRoleRequest {
    return TokenCreateAgainstRoleRequestFromJSONTyped(json, false);
}

export function TokenCreateAgainstRoleRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): TokenCreateAgainstRoleRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'displayName': json['display_name'] == null ? undefined : json['display_name'],
        'entityAlias': json['entity_alias'] == null ? undefined : json['entity_alias'],
        'explicitMaxTtl': json['explicit_max_ttl'] == null ? undefined : json['explicit_max_ttl'],
        'id': json['id'] == null ? undefined : json['id'],
        'lease': json['lease'] == null ? undefined : json['lease'],
        'meta': json['meta'] == null ? undefined : json['meta'],
        'noDefaultPolicy': json['no_default_policy'] == null ? undefined : json['no_default_policy'],
        'noParent': json['no_parent'] == null ? undefined : json['no_parent'],
        'numUses': json['num_uses'] == null ? undefined : json['num_uses'],
        'period': json['period'] == null ? undefined : json['period'],
        'policies': json['policies'] == null ? undefined : json['policies'],
        'renewable': json['renewable'] == null ? undefined : json['renewable'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
        'type': json['type'] == null ? undefined : json['type'],
    };
}

export function TokenCreateAgainstRoleRequestToJSON(json: any): TokenCreateAgainstRoleRequest {
    return TokenCreateAgainstRoleRequestToJSONTyped(json, false);
}

export function TokenCreateAgainstRoleRequestToJSONTyped(value?: TokenCreateAgainstRoleRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'display_name': value['displayName'],
        'entity_alias': value['entityAlias'],
        'explicit_max_ttl': value['explicitMaxTtl'],
        'id': value['id'],
        'lease': value['lease'],
        'meta': value['meta'],
        'no_default_policy': value['noDefaultPolicy'],
        'no_parent': value['noParent'],
        'num_uses': value['numUses'],
        'period': value['period'],
        'policies': value['policies'],
        'renewable': value['renewable'],
        'ttl': value['ttl'],
        'type': value['type'],
    };
}

