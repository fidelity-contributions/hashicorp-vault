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
 * @interface PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest
 */
export interface PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest {
    [key: string]: any | any;
    /**
     * PEM-format CSR is expected but the contents of this field will not be validated
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest
     */
    csr: string;
    /**
     * Format for returned data. Can be "pem", "der", or "pem_bundle". If "pem_bundle", any private key and issuing cert will be appended to the certificate pem. If "der", the value will be base64 encoded. Defaults to "pem".
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest
     */
    format?: PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequestFormatEnum;
}
/**
* @export
* @enum {string}
*/
export declare enum PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequestFormatEnum {
    PEM = "pem",
    DER = "der",
    PEM_BUNDLE = "pem_bundle"
}
/**
 * Check if a given object implements the PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest interface.
 */
export declare function instanceOfPkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest(value: object): value is PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest;
export declare function PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequestFromJSON(json: any): PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest;
export declare function PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest;
export declare function PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequestToJSON(json: any): PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest;
export declare function PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequestToJSONTyped(value?: PkiWriteIssuerIssuerRefExternalPolicySignIntermediateRequest | null, ignoreDiscriminator?: boolean): any;
