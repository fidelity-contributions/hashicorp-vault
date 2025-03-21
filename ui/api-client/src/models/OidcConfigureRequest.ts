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
 * @interface OidcConfigureRequest
 */
export interface OidcConfigureRequest {
    /**
     * Issuer URL to be used in the iss claim of the token. If not set, Vault's app_addr will be used.
     * @type {string}
     * @memberof OidcConfigureRequest
     */
    issuer?: string;
}

/**
 * Check if a given object implements the OidcConfigureRequest interface.
 */
export function instanceOfOidcConfigureRequest(value: object): value is OidcConfigureRequest {
    return true;
}

export function OidcConfigureRequestFromJSON(json: any): OidcConfigureRequest {
    return OidcConfigureRequestFromJSONTyped(json, false);
}

export function OidcConfigureRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): OidcConfigureRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'issuer': json['issuer'] == null ? undefined : json['issuer'],
    };
}

export function OidcConfigureRequestToJSON(json: any): OidcConfigureRequest {
    return OidcConfigureRequestToJSONTyped(json, false);
}

export function OidcConfigureRequestToJSONTyped(value?: OidcConfigureRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'issuer': value['issuer'],
    };
}

