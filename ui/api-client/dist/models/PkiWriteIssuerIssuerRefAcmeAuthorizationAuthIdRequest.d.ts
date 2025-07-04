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
 * @interface PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest
 */
export interface PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest {
    /**
     * ACME request 'payload' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest
     */
    payload?: string;
    /**
     * ACME request 'protected' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest
     */
    _protected?: string;
    /**
     * ACME request 'signature' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest
     */
    signature?: string;
}
/**
 * Check if a given object implements the PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest interface.
 */
export declare function instanceOfPkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest(value: object): value is PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest;
export declare function PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequestFromJSON(json: any): PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest;
export declare function PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest;
export declare function PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequestToJSON(json: any): PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest;
export declare function PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequestToJSONTyped(value?: PkiWriteIssuerIssuerRefAcmeAuthorizationAuthIdRequest | null, ignoreDiscriminator?: boolean): any;
