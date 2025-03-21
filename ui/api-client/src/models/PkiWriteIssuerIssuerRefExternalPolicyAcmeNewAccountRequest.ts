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
 * @interface PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest
 */
export interface PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest {
    /**
     * ACME request 'payload' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest
     */
    payload?: string;
    /**
     * ACME request 'protected' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest
     */
    _protected?: string;
    /**
     * ACME request 'signature' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest
     */
    signature?: string;
}

/**
 * Check if a given object implements the PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest interface.
 */
export function instanceOfPkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest(value: object): value is PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest {
    return true;
}

export function PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequestFromJSON(json: any): PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest {
    return PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequestFromJSONTyped(json, false);
}

export function PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'payload': json['payload'] == null ? undefined : json['payload'],
        '_protected': json['protected'] == null ? undefined : json['protected'],
        'signature': json['signature'] == null ? undefined : json['signature'],
    };
}

export function PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequestToJSON(json: any): PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest {
    return PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequestToJSONTyped(json, false);
}

export function PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequestToJSONTyped(value?: PkiWriteIssuerIssuerRefExternalPolicyAcmeNewAccountRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'payload': value['payload'],
        'protected': value['_protected'],
        'signature': value['signature'],
    };
}

