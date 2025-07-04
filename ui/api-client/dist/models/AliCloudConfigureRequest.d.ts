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
 * @interface AliCloudConfigureRequest
 */
export interface AliCloudConfigureRequest {
    /**
     * Access key with appropriate permissions.
     * @type {string}
     * @memberof AliCloudConfigureRequest
     */
    accessKey?: string;
    /**
     * Secret key with appropriate permissions.
     * @type {string}
     * @memberof AliCloudConfigureRequest
     */
    secretKey?: string;
}
/**
 * Check if a given object implements the AliCloudConfigureRequest interface.
 */
export declare function instanceOfAliCloudConfigureRequest(value: object): value is AliCloudConfigureRequest;
export declare function AliCloudConfigureRequestFromJSON(json: any): AliCloudConfigureRequest;
export declare function AliCloudConfigureRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): AliCloudConfigureRequest;
export declare function AliCloudConfigureRequestToJSON(json: any): AliCloudConfigureRequest;
export declare function AliCloudConfigureRequestToJSONTyped(value?: AliCloudConfigureRequest | null, ignoreDiscriminator?: boolean): any;
