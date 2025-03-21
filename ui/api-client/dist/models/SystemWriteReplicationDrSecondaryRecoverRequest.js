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
exports.instanceOfSystemWriteReplicationDrSecondaryRecoverRequest = instanceOfSystemWriteReplicationDrSecondaryRecoverRequest;
exports.SystemWriteReplicationDrSecondaryRecoverRequestFromJSON = SystemWriteReplicationDrSecondaryRecoverRequestFromJSON;
exports.SystemWriteReplicationDrSecondaryRecoverRequestFromJSONTyped = SystemWriteReplicationDrSecondaryRecoverRequestFromJSONTyped;
exports.SystemWriteReplicationDrSecondaryRecoverRequestToJSON = SystemWriteReplicationDrSecondaryRecoverRequestToJSON;
exports.SystemWriteReplicationDrSecondaryRecoverRequestToJSONTyped = SystemWriteReplicationDrSecondaryRecoverRequestToJSONTyped;
/**
 * Check if a given object implements the SystemWriteReplicationDrSecondaryRecoverRequest interface.
 */
function instanceOfSystemWriteReplicationDrSecondaryRecoverRequest(value) {
    return true;
}
function SystemWriteReplicationDrSecondaryRecoverRequestFromJSON(json) {
    return SystemWriteReplicationDrSecondaryRecoverRequestFromJSONTyped(json, false);
}
function SystemWriteReplicationDrSecondaryRecoverRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'drOperationToken': json['dr_operation_token'] == null ? undefined : json['dr_operation_token'],
    };
}
function SystemWriteReplicationDrSecondaryRecoverRequestToJSON(json) {
    return SystemWriteReplicationDrSecondaryRecoverRequestToJSONTyped(json, false);
}
function SystemWriteReplicationDrSecondaryRecoverRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'dr_operation_token': value['drOperationToken'],
    };
}
