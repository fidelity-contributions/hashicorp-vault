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
 * @interface SystemReadSyncDestinationsInMemNameResponse
 */
export interface SystemReadSyncDestinationsInMemNameResponse {
    /**
     * List of key value pairs of information necessary to connect with the external system.
     * @type {object}
     * @memberof SystemReadSyncDestinationsInMemNameResponse
     */
    connectionDetails?: object;
    /**
     * Name of this secrets store.
     * @type {string}
     * @memberof SystemReadSyncDestinationsInMemNameResponse
     */
    name?: string;
    /**
     * Type of this secrets store.
     * @type {string}
     * @memberof SystemReadSyncDestinationsInMemNameResponse
     */
    type?: string;
}

/**
 * Check if a given object implements the SystemReadSyncDestinationsInMemNameResponse interface.
 */
export function instanceOfSystemReadSyncDestinationsInMemNameResponse(value: object): value is SystemReadSyncDestinationsInMemNameResponse {
    return true;
}

export function SystemReadSyncDestinationsInMemNameResponseFromJSON(json: any): SystemReadSyncDestinationsInMemNameResponse {
    return SystemReadSyncDestinationsInMemNameResponseFromJSONTyped(json, false);
}

export function SystemReadSyncDestinationsInMemNameResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): SystemReadSyncDestinationsInMemNameResponse {
    if (json == null) {
        return json;
    }
    return {
        
        'connectionDetails': json['connection_details'] == null ? undefined : json['connection_details'],
        'name': json['name'] == null ? undefined : json['name'],
        'type': json['type'] == null ? undefined : json['type'],
    };
}

export function SystemReadSyncDestinationsInMemNameResponseToJSON(json: any): SystemReadSyncDestinationsInMemNameResponse {
    return SystemReadSyncDestinationsInMemNameResponseToJSONTyped(json, false);
}

export function SystemReadSyncDestinationsInMemNameResponseToJSONTyped(value?: SystemReadSyncDestinationsInMemNameResponse | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'connection_details': value['connectionDetails'],
        'name': value['name'],
        'type': value['type'],
    };
}

