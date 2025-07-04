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
 * @interface UiConfigReadCustomMessageResponse
 */
export interface UiConfigReadCustomMessageResponse {
    /**
     *
     * @type {boolean}
     * @memberof UiConfigReadCustomMessageResponse
     */
    active?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof UiConfigReadCustomMessageResponse
     */
    authenticated?: boolean;
    /**
     *
     * @type {Date}
     * @memberof UiConfigReadCustomMessageResponse
     */
    endTime?: Date;
    /**
     *
     * @type {string}
     * @memberof UiConfigReadCustomMessageResponse
     */
    id?: string;
    /**
     *
     * @type {object}
     * @memberof UiConfigReadCustomMessageResponse
     */
    link?: object;
    /**
     *
     * @type {string}
     * @memberof UiConfigReadCustomMessageResponse
     */
    message?: string;
    /**
     *
     * @type {object}
     * @memberof UiConfigReadCustomMessageResponse
     */
    options?: object;
    /**
     *
     * @type {Date}
     * @memberof UiConfigReadCustomMessageResponse
     */
    startTime?: Date;
    /**
     *
     * @type {string}
     * @memberof UiConfigReadCustomMessageResponse
     */
    title?: string;
    /**
     *
     * @type {boolean}
     * @memberof UiConfigReadCustomMessageResponse
     */
    type?: boolean;
}
/**
 * Check if a given object implements the UiConfigReadCustomMessageResponse interface.
 */
export declare function instanceOfUiConfigReadCustomMessageResponse(value: object): value is UiConfigReadCustomMessageResponse;
export declare function UiConfigReadCustomMessageResponseFromJSON(json: any): UiConfigReadCustomMessageResponse;
export declare function UiConfigReadCustomMessageResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): UiConfigReadCustomMessageResponse;
export declare function UiConfigReadCustomMessageResponseToJSON(json: any): UiConfigReadCustomMessageResponse;
export declare function UiConfigReadCustomMessageResponseToJSONTyped(value?: UiConfigReadCustomMessageResponse | null, ignoreDiscriminator?: boolean): any;
