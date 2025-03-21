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
 * @interface RootTokenGenerationUpdateResponse
 */
export interface RootTokenGenerationUpdateResponse {
    /**
     * 
     * @type {boolean}
     * @memberof RootTokenGenerationUpdateResponse
     */
    complete?: boolean;
    /**
     * 
     * @type {string}
     * @memberof RootTokenGenerationUpdateResponse
     */
    encodedRootToken?: string;
    /**
     * 
     * @type {string}
     * @memberof RootTokenGenerationUpdateResponse
     */
    encodedToken?: string;
    /**
     * 
     * @type {string}
     * @memberof RootTokenGenerationUpdateResponse
     */
    nonce?: string;
    /**
     * 
     * @type {string}
     * @memberof RootTokenGenerationUpdateResponse
     */
    otp?: string;
    /**
     * 
     * @type {number}
     * @memberof RootTokenGenerationUpdateResponse
     */
    otpLength?: number;
    /**
     * 
     * @type {string}
     * @memberof RootTokenGenerationUpdateResponse
     */
    pgpFingerprint?: string;
    /**
     * 
     * @type {number}
     * @memberof RootTokenGenerationUpdateResponse
     */
    progress?: number;
    /**
     * 
     * @type {number}
     * @memberof RootTokenGenerationUpdateResponse
     */
    required?: number;
    /**
     * 
     * @type {boolean}
     * @memberof RootTokenGenerationUpdateResponse
     */
    started?: boolean;
}

/**
 * Check if a given object implements the RootTokenGenerationUpdateResponse interface.
 */
export function instanceOfRootTokenGenerationUpdateResponse(value: object): value is RootTokenGenerationUpdateResponse {
    return true;
}

export function RootTokenGenerationUpdateResponseFromJSON(json: any): RootTokenGenerationUpdateResponse {
    return RootTokenGenerationUpdateResponseFromJSONTyped(json, false);
}

export function RootTokenGenerationUpdateResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): RootTokenGenerationUpdateResponse {
    if (json == null) {
        return json;
    }
    return {
        
        'complete': json['complete'] == null ? undefined : json['complete'],
        'encodedRootToken': json['encoded_root_token'] == null ? undefined : json['encoded_root_token'],
        'encodedToken': json['encoded_token'] == null ? undefined : json['encoded_token'],
        'nonce': json['nonce'] == null ? undefined : json['nonce'],
        'otp': json['otp'] == null ? undefined : json['otp'],
        'otpLength': json['otp_length'] == null ? undefined : json['otp_length'],
        'pgpFingerprint': json['pgp_fingerprint'] == null ? undefined : json['pgp_fingerprint'],
        'progress': json['progress'] == null ? undefined : json['progress'],
        'required': json['required'] == null ? undefined : json['required'],
        'started': json['started'] == null ? undefined : json['started'],
    };
}

export function RootTokenGenerationUpdateResponseToJSON(json: any): RootTokenGenerationUpdateResponse {
    return RootTokenGenerationUpdateResponseToJSONTyped(json, false);
}

export function RootTokenGenerationUpdateResponseToJSONTyped(value?: RootTokenGenerationUpdateResponse | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'complete': value['complete'],
        'encoded_root_token': value['encodedRootToken'],
        'encoded_token': value['encodedToken'],
        'nonce': value['nonce'],
        'otp': value['otp'],
        'otp_length': value['otpLength'],
        'pgp_fingerprint': value['pgpFingerprint'],
        'progress': value['progress'],
        'required': value['required'],
        'started': value['started'],
    };
}

