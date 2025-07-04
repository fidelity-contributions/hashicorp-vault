/**
 * HashiCorp Vault API
 * HTTP API that gives you full access to Vault. All API routes are prefixed with `/v1/`.
 *
 * The version of the OpenAPI document: 1.21.0
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
/**
 *
 * @export
 * @interface KmipConfigureRequest
 */
export interface KmipConfigureRequest {
    /**
     * Client certificate key bits, valid values depend on key type
     * @type {number}
     * @memberof KmipConfigureRequest
     */
    defaultTlsClientKeyBits?: number;
    /**
     * Client certificate key type, rsa or ec
     * @type {string}
     * @memberof KmipConfigureRequest
     */
    defaultTlsClientKeyType?: KmipConfigureRequestDefaultTlsClientKeyTypeEnum;
    /**
     * Client certificate TTL in either an integer number of seconds (3600) or an integer time unit (1h)
     * @type {string}
     * @memberof KmipConfigureRequest
     */
    defaultTlsClientTtl?: string;
    /**
     * A list of address:port to listen on. A bare address without port may be provided, in which case port 5696 is assumed.
     * @type {Array<string>}
     * @memberof KmipConfigureRequest
     */
    listenAddrs?: Array<string>;
    /**
     * A list of hostnames to include in the server's TLS certificate as SAN DNS names. The first will be used as the common name (CN).
     * @type {Array<string>}
     * @memberof KmipConfigureRequest
     */
    serverHostnames?: Array<string>;
    /**
     * A list of IP to include in the server's TLS certificate as SAN IP addresses.
     * @type {Array<string>}
     * @memberof KmipConfigureRequest
     */
    serverIps?: Array<string>;
    /**
     * CA key bits, valid values depend on key type
     * @type {number}
     * @memberof KmipConfigureRequest
     */
    tlsCaKeyBits?: number;
    /**
     * CA key type, rsa or ec
     * @type {string}
     * @memberof KmipConfigureRequest
     */
    tlsCaKeyType?: KmipConfigureRequestTlsCaKeyTypeEnum;
    /**
     * Min TLS version
     * @type {string}
     * @memberof KmipConfigureRequest
     */
    tlsMinVersion?: string;
}
/**
* @export
* @enum {string}
*/
export declare enum KmipConfigureRequestDefaultTlsClientKeyTypeEnum {
    RSA = "rsa",
    EC = "ec"
}
/**
* @export
* @enum {string}
*/
export declare enum KmipConfigureRequestTlsCaKeyTypeEnum {
    RSA = "rsa",
    EC = "ec"
}
/**
 * Check if a given object implements the KmipConfigureRequest interface.
 */
export declare function instanceOfKmipConfigureRequest(value: object): value is KmipConfigureRequest;
export declare function KmipConfigureRequestFromJSON(json: any): KmipConfigureRequest;
export declare function KmipConfigureRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): KmipConfigureRequest;
export declare function KmipConfigureRequestToJSON(json: any): KmipConfigureRequest;
export declare function KmipConfigureRequestToJSONTyped(value?: KmipConfigureRequest | null, ignoreDiscriminator?: boolean): any;
