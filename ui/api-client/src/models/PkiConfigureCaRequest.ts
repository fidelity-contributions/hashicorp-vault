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
 * @interface PkiConfigureCaRequest
 */
export interface PkiConfigureCaRequest {
    /**
     * PEM-format, concatenated unencrypted secret key and certificate.
     * @type {string}
     * @memberof PkiConfigureCaRequest
     */
    pemBundle?: string;
}

/**
 * Check if a given object implements the PkiConfigureCaRequest interface.
 */
export function instanceOfPkiConfigureCaRequest(value: object): value is PkiConfigureCaRequest {
    return true;
}

export function PkiConfigureCaRequestFromJSON(json: any): PkiConfigureCaRequest {
    return PkiConfigureCaRequestFromJSONTyped(json, false);
}

export function PkiConfigureCaRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiConfigureCaRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'pemBundle': json['pem_bundle'] == null ? undefined : json['pem_bundle'],
    };
}

export function PkiConfigureCaRequestToJSON(json: any): PkiConfigureCaRequest {
    return PkiConfigureCaRequestToJSONTyped(json, false);
}

export function PkiConfigureCaRequestToJSONTyped(value?: PkiConfigureCaRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'pem_bundle': value['pemBundle'],
    };
}

