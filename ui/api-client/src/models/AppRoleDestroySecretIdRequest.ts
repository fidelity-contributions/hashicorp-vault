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
 * @interface AppRoleDestroySecretIdRequest
 */
export interface AppRoleDestroySecretIdRequest {
    /**
     * SecretID attached to the role.
     * @type {string}
     * @memberof AppRoleDestroySecretIdRequest
     */
    secretId?: string;
}

/**
 * Check if a given object implements the AppRoleDestroySecretIdRequest interface.
 */
export function instanceOfAppRoleDestroySecretIdRequest(value: object): value is AppRoleDestroySecretIdRequest {
    return true;
}

export function AppRoleDestroySecretIdRequestFromJSON(json: any): AppRoleDestroySecretIdRequest {
    return AppRoleDestroySecretIdRequestFromJSONTyped(json, false);
}

export function AppRoleDestroySecretIdRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): AppRoleDestroySecretIdRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'secretId': json['secret_id'] == null ? undefined : json['secret_id'],
    };
}

export function AppRoleDestroySecretIdRequestToJSON(json: any): AppRoleDestroySecretIdRequest {
    return AppRoleDestroySecretIdRequestToJSONTyped(json, false);
}

export function AppRoleDestroySecretIdRequestToJSONTyped(value?: AppRoleDestroySecretIdRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'secret_id': value['secretId'],
    };
}

