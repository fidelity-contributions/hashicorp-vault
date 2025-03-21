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
 * @interface AliasCreateRequest
 */
export interface AliasCreateRequest {
    /**
     * Entity ID to which this alias belongs to
     * @type {string}
     * @memberof AliasCreateRequest
     */
    canonicalId?: string;
    /**
     * Entity ID to which this alias belongs to. This field is deprecated in favor of 'canonical_id'.
     * @type {string}
     * @memberof AliasCreateRequest
     */
    entityId?: string;
    /**
     * ID of the alias
     * @type {string}
     * @memberof AliasCreateRequest
     */
    id?: string;
    /**
     * Mount accessor to which this alias belongs to
     * @type {string}
     * @memberof AliasCreateRequest
     */
    mountAccessor?: string;
    /**
     * Name of the alias
     * @type {string}
     * @memberof AliasCreateRequest
     */
    name?: string;
}

/**
 * Check if a given object implements the AliasCreateRequest interface.
 */
export function instanceOfAliasCreateRequest(value: object): value is AliasCreateRequest {
    return true;
}

export function AliasCreateRequestFromJSON(json: any): AliasCreateRequest {
    return AliasCreateRequestFromJSONTyped(json, false);
}

export function AliasCreateRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): AliasCreateRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'canonicalId': json['canonical_id'] == null ? undefined : json['canonical_id'],
        'entityId': json['entity_id'] == null ? undefined : json['entity_id'],
        'id': json['id'] == null ? undefined : json['id'],
        'mountAccessor': json['mount_accessor'] == null ? undefined : json['mount_accessor'],
        'name': json['name'] == null ? undefined : json['name'],
    };
}

export function AliasCreateRequestToJSON(json: any): AliasCreateRequest {
    return AliasCreateRequestToJSONTyped(json, false);
}

export function AliasCreateRequestToJSONTyped(value?: AliasCreateRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'canonical_id': value['canonicalId'],
        'entity_id': value['entityId'],
        'id': value['id'],
        'mount_accessor': value['mountAccessor'],
        'name': value['name'],
    };
}

