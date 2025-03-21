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
 * @interface PkiIssuerSignWithRoleResponse
 */
export interface PkiIssuerSignWithRoleResponse {
    /**
     * Certificate Chain
     * @type {Array<string>}
     * @memberof PkiIssuerSignWithRoleResponse
     */
    caChain?: Array<string>;
    /**
     * Certificate
     * @type {string}
     * @memberof PkiIssuerSignWithRoleResponse
     */
    certificate?: string;
    /**
     * Time of expiration
     * @type {number}
     * @memberof PkiIssuerSignWithRoleResponse
     */
    expiration?: number;
    /**
     * Issuing Certificate Authority
     * @type {string}
     * @memberof PkiIssuerSignWithRoleResponse
     */
    issuingCa?: string;
    /**
     * Serial Number
     * @type {string}
     * @memberof PkiIssuerSignWithRoleResponse
     */
    serialNumber?: string;
}

/**
 * Check if a given object implements the PkiIssuerSignWithRoleResponse interface.
 */
export function instanceOfPkiIssuerSignWithRoleResponse(value: object): value is PkiIssuerSignWithRoleResponse {
    return true;
}

export function PkiIssuerSignWithRoleResponseFromJSON(json: any): PkiIssuerSignWithRoleResponse {
    return PkiIssuerSignWithRoleResponseFromJSONTyped(json, false);
}

export function PkiIssuerSignWithRoleResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiIssuerSignWithRoleResponse {
    if (json == null) {
        return json;
    }
    return {
        
        'caChain': json['ca_chain'] == null ? undefined : json['ca_chain'],
        'certificate': json['certificate'] == null ? undefined : json['certificate'],
        'expiration': json['expiration'] == null ? undefined : json['expiration'],
        'issuingCa': json['issuing_ca'] == null ? undefined : json['issuing_ca'],
        'serialNumber': json['serial_number'] == null ? undefined : json['serial_number'],
    };
}

export function PkiIssuerSignWithRoleResponseToJSON(json: any): PkiIssuerSignWithRoleResponse {
    return PkiIssuerSignWithRoleResponseToJSONTyped(json, false);
}

export function PkiIssuerSignWithRoleResponseToJSONTyped(value?: PkiIssuerSignWithRoleResponse | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'ca_chain': value['caChain'],
        'certificate': value['certificate'],
        'expiration': value['expiration'],
        'issuing_ca': value['issuingCa'],
        'serial_number': value['serialNumber'],
    };
}

