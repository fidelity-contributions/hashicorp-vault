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
 * @interface MfaGenerateTotpSecretRequest
 */
export interface MfaGenerateTotpSecretRequest {
    /**
     * The unique identifier for this MFA method.
     * @type {string}
     * @memberof MfaGenerateTotpSecretRequest
     */
    methodId: string;
}

/**
 * Check if a given object implements the MfaGenerateTotpSecretRequest interface.
 */
export function instanceOfMfaGenerateTotpSecretRequest(value: object): value is MfaGenerateTotpSecretRequest {
    if (!('methodId' in value) || value['methodId'] === undefined) return false;
    return true;
}

export function MfaGenerateTotpSecretRequestFromJSON(json: any): MfaGenerateTotpSecretRequest {
    return MfaGenerateTotpSecretRequestFromJSONTyped(json, false);
}

export function MfaGenerateTotpSecretRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): MfaGenerateTotpSecretRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'methodId': json['method_id'],
    };
}

export function MfaGenerateTotpSecretRequestToJSON(json: any): MfaGenerateTotpSecretRequest {
    return MfaGenerateTotpSecretRequestToJSONTyped(json, false);
}

export function MfaGenerateTotpSecretRequestToJSONTyped(value?: MfaGenerateTotpSecretRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'method_id': value['methodId'],
    };
}

