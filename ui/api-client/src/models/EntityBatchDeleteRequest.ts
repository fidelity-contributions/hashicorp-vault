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
 * @interface EntityBatchDeleteRequest
 */
export interface EntityBatchDeleteRequest {
    /**
     * Entity IDs to delete
     * @type {Array<string>}
     * @memberof EntityBatchDeleteRequest
     */
    entityIds?: Array<string>;
}

/**
 * Check if a given object implements the EntityBatchDeleteRequest interface.
 */
export function instanceOfEntityBatchDeleteRequest(value: object): value is EntityBatchDeleteRequest {
    return true;
}

export function EntityBatchDeleteRequestFromJSON(json: any): EntityBatchDeleteRequest {
    return EntityBatchDeleteRequestFromJSONTyped(json, false);
}

export function EntityBatchDeleteRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): EntityBatchDeleteRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'entityIds': json['entity_ids'] == null ? undefined : json['entity_ids'],
    };
}

export function EntityBatchDeleteRequestToJSON(json: any): EntityBatchDeleteRequest {
    return EntityBatchDeleteRequestToJSONTyped(json, false);
}

export function EntityBatchDeleteRequestToJSONTyped(value?: EntityBatchDeleteRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'entity_ids': value['entityIds'],
    };
}

