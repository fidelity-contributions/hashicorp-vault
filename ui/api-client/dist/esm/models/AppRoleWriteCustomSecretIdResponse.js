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
/**
 * Check if a given object implements the AppRoleWriteCustomSecretIdResponse interface.
 */
export function instanceOfAppRoleWriteCustomSecretIdResponse(value) {
    return true;
}
export function AppRoleWriteCustomSecretIdResponseFromJSON(json) {
    return AppRoleWriteCustomSecretIdResponseFromJSONTyped(json, false);
}
export function AppRoleWriteCustomSecretIdResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'secretId': json['secret_id'] == null ? undefined : json['secret_id'],
        'secretIdAccessor': json['secret_id_accessor'] == null ? undefined : json['secret_id_accessor'],
        'secretIdNumUses': json['secret_id_num_uses'] == null ? undefined : json['secret_id_num_uses'],
        'secretIdTtl': json['secret_id_ttl'] == null ? undefined : json['secret_id_ttl'],
    };
}
export function AppRoleWriteCustomSecretIdResponseToJSON(json) {
    return AppRoleWriteCustomSecretIdResponseToJSONTyped(json, false);
}
export function AppRoleWriteCustomSecretIdResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'secret_id': value['secretId'],
        'secret_id_accessor': value['secretIdAccessor'],
        'secret_id_num_uses': value['secretIdNumUses'],
        'secret_id_ttl': value['secretIdTtl'],
    };
}
