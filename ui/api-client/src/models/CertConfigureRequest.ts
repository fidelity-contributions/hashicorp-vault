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
 * @interface CertConfigureRequest
 */
export interface CertConfigureRequest {
    /**
     * If set, during renewal, skips the matching of presented client identity with the client identity used during login. Defaults to false.
     * @type {boolean}
     * @memberof CertConfigureRequest
     */
    disableBinding?: boolean;
    /**
     * If set, metadata of the certificate including the metadata corresponding to allowed_metadata_extensions will be stored in the alias. Defaults to false.
     * @type {boolean}
     * @memberof CertConfigureRequest
     */
    enableIdentityAliasMetadata?: boolean;
    /**
     * If set, metadata of the client certificate will be returned on authentication failures.
     * @type {boolean}
     * @memberof CertConfigureRequest
     */
    enableMetadataOnFailures?: boolean;
    /**
     * The size of the in memory OCSP response cache, shared by all configured certs
     * @type {number}
     * @memberof CertConfigureRequest
     */
    ocspCacheSize?: number;
    /**
     * The size of the in memory role cache
     * @type {number}
     * @memberof CertConfigureRequest
     */
    roleCacheSize?: number;
}

/**
 * Check if a given object implements the CertConfigureRequest interface.
 */
export function instanceOfCertConfigureRequest(value: object): value is CertConfigureRequest {
    return true;
}

export function CertConfigureRequestFromJSON(json: any): CertConfigureRequest {
    return CertConfigureRequestFromJSONTyped(json, false);
}

export function CertConfigureRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): CertConfigureRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'disableBinding': json['disable_binding'] == null ? undefined : json['disable_binding'],
        'enableIdentityAliasMetadata': json['enable_identity_alias_metadata'] == null ? undefined : json['enable_identity_alias_metadata'],
        'enableMetadataOnFailures': json['enable_metadata_on_failures'] == null ? undefined : json['enable_metadata_on_failures'],
        'ocspCacheSize': json['ocsp_cache_size'] == null ? undefined : json['ocsp_cache_size'],
        'roleCacheSize': json['role_cache_size'] == null ? undefined : json['role_cache_size'],
    };
}

export function CertConfigureRequestToJSON(json: any): CertConfigureRequest {
    return CertConfigureRequestToJSONTyped(json, false);
}

export function CertConfigureRequestToJSONTyped(value?: CertConfigureRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'disable_binding': value['disableBinding'],
        'enable_identity_alias_metadata': value['enableIdentityAliasMetadata'],
        'enable_metadata_on_failures': value['enableMetadataOnFailures'],
        'ocsp_cache_size': value['ocspCacheSize'],
        'role_cache_size': value['roleCacheSize'],
    };
}

