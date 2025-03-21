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
 * @interface PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest
 */
export interface PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest {
    /**
     * ACME request 'payload' value
     * @type {string}
     * @memberof PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest
     */
    payload?: string;
    /**
     * ACME request 'protected' value
     * @type {string}
     * @memberof PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest
     */
    _protected?: string;
    /**
     * ACME request 'signature' value
     * @type {string}
     * @memberof PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest
     */
    signature?: string;
}

/**
 * Check if a given object implements the PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest interface.
 */
export function instanceOfPkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest(value: object): value is PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest {
    return true;
}

export function PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequestFromJSON(json: any): PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest {
    return PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequestFromJSONTyped(json, false);
}

export function PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'payload': json['payload'] == null ? undefined : json['payload'],
        '_protected': json['protected'] == null ? undefined : json['protected'],
        'signature': json['signature'] == null ? undefined : json['signature'],
    };
}

export function PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequestToJSON(json: any): PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest {
    return PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequestToJSONTyped(json, false);
}

export function PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequestToJSONTyped(value?: PkiWriteExternalPolicyPolicyAcmeOrderOrderIdFinalizeRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'payload': value['payload'],
        'protected': value['_protected'],
        'signature': value['signature'],
    };
}

