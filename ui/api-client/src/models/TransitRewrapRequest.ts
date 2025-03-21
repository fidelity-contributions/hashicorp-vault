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
 * @interface TransitRewrapRequest
 */
export interface TransitRewrapRequest {
    /**
     * Specifies a list of items to be re-encrypted in a single batch. When this parameter is set, if the parameters 'ciphertext', 'context' and 'nonce' are also set, they will be ignored. Any batch output will preserve the order of the batch input.
     * @type {Array<object>}
     * @memberof TransitRewrapRequest
     */
    batchInput?: Array<object>;
    /**
     * Ciphertext value to rewrap
     * @type {string}
     * @memberof TransitRewrapRequest
     */
    ciphertext?: string;
    /**
     * Base64 encoded context for key derivation. Required for derived keys.
     * @type {string}
     * @memberof TransitRewrapRequest
     */
    context?: string;
    /**
     * The padding scheme to use for rewrap's decrypt step. Currently only applies to RSA key types. Options are 'oaep' or 'pkcs1v15'. Defaults to 'oaep'
     * @type {string}
     * @memberof TransitRewrapRequest
     */
    decryptPaddingScheme?: string;
    /**
     * The padding scheme to use for rewrap's encrypt step. Currently only applies to RSA key types. Options are 'oaep' or 'pkcs1v15'. Defaults to 'oaep'
     * @type {string}
     * @memberof TransitRewrapRequest
     */
    encryptPaddingScheme?: string;
    /**
     * The version of the key to use for encryption. Must be 0 (for latest) or a value greater than or equal to the min_encryption_version configured on the key.
     * @type {number}
     * @memberof TransitRewrapRequest
     */
    keyVersion?: number;
    /**
     * Nonce for when convergent encryption is used
     * @type {string}
     * @memberof TransitRewrapRequest
     */
    nonce?: string;
}

/**
 * Check if a given object implements the TransitRewrapRequest interface.
 */
export function instanceOfTransitRewrapRequest(value: object): value is TransitRewrapRequest {
    return true;
}

export function TransitRewrapRequestFromJSON(json: any): TransitRewrapRequest {
    return TransitRewrapRequestFromJSONTyped(json, false);
}

export function TransitRewrapRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): TransitRewrapRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'batchInput': json['batch_input'] == null ? undefined : json['batch_input'],
        'ciphertext': json['ciphertext'] == null ? undefined : json['ciphertext'],
        'context': json['context'] == null ? undefined : json['context'],
        'decryptPaddingScheme': json['decrypt_padding_scheme'] == null ? undefined : json['decrypt_padding_scheme'],
        'encryptPaddingScheme': json['encrypt_padding_scheme'] == null ? undefined : json['encrypt_padding_scheme'],
        'keyVersion': json['key_version'] == null ? undefined : json['key_version'],
        'nonce': json['nonce'] == null ? undefined : json['nonce'],
    };
}

export function TransitRewrapRequestToJSON(json: any): TransitRewrapRequest {
    return TransitRewrapRequestToJSONTyped(json, false);
}

export function TransitRewrapRequestToJSONTyped(value?: TransitRewrapRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'batch_input': value['batchInput'],
        'ciphertext': value['ciphertext'],
        'context': value['context'],
        'decrypt_padding_scheme': value['decryptPaddingScheme'],
        'encrypt_padding_scheme': value['encryptPaddingScheme'],
        'key_version': value['keyVersion'],
        'nonce': value['nonce'],
    };
}

