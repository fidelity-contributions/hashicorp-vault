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
 * @interface DatabaseWriteRoleRequest
 */
export interface DatabaseWriteRoleRequest {
    /**
     * Specifies the database statements executed to create and configure a user. See the plugin's API page for more information on support and formatting for this parameter.
     * @type {Array<string>}
     * @memberof DatabaseWriteRoleRequest
     */
    creationStatements?: Array<string>;
    /**
     * The configuration for the given credential_type.
     * @type {object}
     * @memberof DatabaseWriteRoleRequest
     */
    credentialConfig?: object;
    /**
     * The type of credential to manage. Options include: 'password', 'rsa_private_key'. Defaults to 'password'.
     * @type {string}
     * @memberof DatabaseWriteRoleRequest
     */
    credentialType?: string;
    /**
     * Name of the database this role acts on.
     * @type {string}
     * @memberof DatabaseWriteRoleRequest
     */
    dbName?: string;
    /**
     * Default ttl for role.
     * @type {string}
     * @memberof DatabaseWriteRoleRequest
     */
    defaultTtl?: string;
    /**
     * Maximum time a credential is valid for
     * @type {string}
     * @memberof DatabaseWriteRoleRequest
     */
    maxTtl?: string;
    /**
     * Specifies the database statements to be executed to renew a user. Not every plugin type will support this functionality. See the plugin's API page for more information on support and formatting for this parameter.
     * @type {Array<string>}
     * @memberof DatabaseWriteRoleRequest
     */
    renewStatements?: Array<string>;
    /**
     * Specifies the database statements to be executed to revoke a user. See the plugin's API page for more information on support and formatting for this parameter.
     * @type {Array<string>}
     * @memberof DatabaseWriteRoleRequest
     */
    revocationStatements?: Array<string>;
    /**
     * Specifies the database statements to be executed rollback a create operation in the event of an error. Not every plugin type will support this functionality. See the plugin's API page for more information on support and formatting for this parameter.
     * @type {Array<string>}
     * @memberof DatabaseWriteRoleRequest
     */
    rollbackStatements?: Array<string>;
}
/**
 * Check if a given object implements the DatabaseWriteRoleRequest interface.
 */
export declare function instanceOfDatabaseWriteRoleRequest(value: object): value is DatabaseWriteRoleRequest;
export declare function DatabaseWriteRoleRequestFromJSON(json: any): DatabaseWriteRoleRequest;
export declare function DatabaseWriteRoleRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): DatabaseWriteRoleRequest;
export declare function DatabaseWriteRoleRequestToJSON(json: any): DatabaseWriteRoleRequest;
export declare function DatabaseWriteRoleRequestToJSONTyped(value?: DatabaseWriteRoleRequest | null, ignoreDiscriminator?: boolean): any;
