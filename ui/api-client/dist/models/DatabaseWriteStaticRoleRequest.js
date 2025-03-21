"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.instanceOfDatabaseWriteStaticRoleRequest = instanceOfDatabaseWriteStaticRoleRequest;
exports.DatabaseWriteStaticRoleRequestFromJSON = DatabaseWriteStaticRoleRequestFromJSON;
exports.DatabaseWriteStaticRoleRequestFromJSONTyped = DatabaseWriteStaticRoleRequestFromJSONTyped;
exports.DatabaseWriteStaticRoleRequestToJSON = DatabaseWriteStaticRoleRequestToJSON;
exports.DatabaseWriteStaticRoleRequestToJSONTyped = DatabaseWriteStaticRoleRequestToJSONTyped;
/**
 * Check if a given object implements the DatabaseWriteStaticRoleRequest interface.
 */
function instanceOfDatabaseWriteStaticRoleRequest(value) {
    return true;
}
function DatabaseWriteStaticRoleRequestFromJSON(json) {
    return DatabaseWriteStaticRoleRequestFromJSONTyped(json, false);
}
function DatabaseWriteStaticRoleRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'credentialConfig': json['credential_config'] == null ? undefined : json['credential_config'],
        'credentialType': json['credential_type'] == null ? undefined : json['credential_type'],
        'dbName': json['db_name'] == null ? undefined : json['db_name'],
        'password': json['password'] == null ? undefined : json['password'],
        'rotationPeriod': json['rotation_period'] == null ? undefined : json['rotation_period'],
        'rotationSchedule': json['rotation_schedule'] == null ? undefined : json['rotation_schedule'],
        'rotationStatements': json['rotation_statements'] == null ? undefined : json['rotation_statements'],
        'rotationWindow': json['rotation_window'] == null ? undefined : json['rotation_window'],
        'selfManagedPassword': json['self_managed_password'] == null ? undefined : json['self_managed_password'],
        'skipImportRotation': json['skip_import_rotation'] == null ? undefined : json['skip_import_rotation'],
        'username': json['username'] == null ? undefined : json['username'],
    };
}
function DatabaseWriteStaticRoleRequestToJSON(json) {
    return DatabaseWriteStaticRoleRequestToJSONTyped(json, false);
}
function DatabaseWriteStaticRoleRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'credential_config': value['credentialConfig'],
        'credential_type': value['credentialType'],
        'db_name': value['dbName'],
        'password': value['password'],
        'rotation_period': value['rotationPeriod'],
        'rotation_schedule': value['rotationSchedule'],
        'rotation_statements': value['rotationStatements'],
        'rotation_window': value['rotationWindow'],
        'self_managed_password': value['selfManagedPassword'],
        'skip_import_rotation': value['skipImportRotation'],
        'username': value['username'],
    };
}
