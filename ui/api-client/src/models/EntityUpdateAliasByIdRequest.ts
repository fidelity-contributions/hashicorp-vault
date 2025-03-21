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
 * @interface EntityUpdateAliasByIdRequest
 */
export interface EntityUpdateAliasByIdRequest {
    /**
     * Entity ID to which this alias should be tied to
     * @type {string}
     * @memberof EntityUpdateAliasByIdRequest
     */
    canonicalId?: string;
    /**
     * User provided key-value pairs
     * @type {object}
     * @memberof EntityUpdateAliasByIdRequest
     */
    customMetadata?: object;
    /**
     * Entity ID to which this alias belongs to. This field is deprecated, use canonical_id.
     * @type {string}
     * @memberof EntityUpdateAliasByIdRequest
     */
    entityId?: string;
    /**
     * (Unused)
     * @type {string}
     * @memberof EntityUpdateAliasByIdRequest
     */
    mountAccessor?: string;
    /**
     * (Unused)
     * @type {string}
     * @memberof EntityUpdateAliasByIdRequest
     */
    name?: string;
}

/**
 * Check if a given object implements the EntityUpdateAliasByIdRequest interface.
 */
export function instanceOfEntityUpdateAliasByIdRequest(value: object): value is EntityUpdateAliasByIdRequest {
    return true;
}

export function EntityUpdateAliasByIdRequestFromJSON(json: any): EntityUpdateAliasByIdRequest {
    return EntityUpdateAliasByIdRequestFromJSONTyped(json, false);
}

export function EntityUpdateAliasByIdRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): EntityUpdateAliasByIdRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'canonicalId': json['canonical_id'] == null ? undefined : json['canonical_id'],
        'customMetadata': json['custom_metadata'] == null ? undefined : json['custom_metadata'],
        'entityId': json['entity_id'] == null ? undefined : json['entity_id'],
        'mountAccessor': json['mount_accessor'] == null ? undefined : json['mount_accessor'],
        'name': json['name'] == null ? undefined : json['name'],
    };
}

export function EntityUpdateAliasByIdRequestToJSON(json: any): EntityUpdateAliasByIdRequest {
    return EntityUpdateAliasByIdRequestToJSONTyped(json, false);
}

export function EntityUpdateAliasByIdRequestToJSONTyped(value?: EntityUpdateAliasByIdRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'canonical_id': value['canonicalId'],
        'custom_metadata': value['customMetadata'],
        'entity_id': value['entityId'],
        'mount_accessor': value['mountAccessor'],
        'name': value['name'],
    };
}

