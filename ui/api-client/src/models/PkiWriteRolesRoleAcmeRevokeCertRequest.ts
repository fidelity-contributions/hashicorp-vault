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
 * @interface PkiWriteRolesRoleAcmeRevokeCertRequest
 */
export interface PkiWriteRolesRoleAcmeRevokeCertRequest {
    /**
     * ACME request 'payload' value
     * @type {string}
     * @memberof PkiWriteRolesRoleAcmeRevokeCertRequest
     */
    payload?: string;
    /**
     * ACME request 'protected' value
     * @type {string}
     * @memberof PkiWriteRolesRoleAcmeRevokeCertRequest
     */
    _protected?: string;
    /**
     * ACME request 'signature' value
     * @type {string}
     * @memberof PkiWriteRolesRoleAcmeRevokeCertRequest
     */
    signature?: string;
}

/**
 * Check if a given object implements the PkiWriteRolesRoleAcmeRevokeCertRequest interface.
 */
export function instanceOfPkiWriteRolesRoleAcmeRevokeCertRequest(value: object): value is PkiWriteRolesRoleAcmeRevokeCertRequest {
    return true;
}

export function PkiWriteRolesRoleAcmeRevokeCertRequestFromJSON(json: any): PkiWriteRolesRoleAcmeRevokeCertRequest {
    return PkiWriteRolesRoleAcmeRevokeCertRequestFromJSONTyped(json, false);
}

export function PkiWriteRolesRoleAcmeRevokeCertRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiWriteRolesRoleAcmeRevokeCertRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'payload': json['payload'] == null ? undefined : json['payload'],
        '_protected': json['protected'] == null ? undefined : json['protected'],
        'signature': json['signature'] == null ? undefined : json['signature'],
    };
}

export function PkiWriteRolesRoleAcmeRevokeCertRequestToJSON(json: any): PkiWriteRolesRoleAcmeRevokeCertRequest {
    return PkiWriteRolesRoleAcmeRevokeCertRequestToJSONTyped(json, false);
}

export function PkiWriteRolesRoleAcmeRevokeCertRequestToJSONTyped(value?: PkiWriteRolesRoleAcmeRevokeCertRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'payload': value['payload'],
        'protected': value['_protected'],
        'signature': value['signature'],
    };
}

