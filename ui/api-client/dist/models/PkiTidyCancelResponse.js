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
exports.instanceOfPkiTidyCancelResponse = instanceOfPkiTidyCancelResponse;
exports.PkiTidyCancelResponseFromJSON = PkiTidyCancelResponseFromJSON;
exports.PkiTidyCancelResponseFromJSONTyped = PkiTidyCancelResponseFromJSONTyped;
exports.PkiTidyCancelResponseToJSON = PkiTidyCancelResponseToJSON;
exports.PkiTidyCancelResponseToJSONTyped = PkiTidyCancelResponseToJSONTyped;
/**
 * Check if a given object implements the PkiTidyCancelResponse interface.
 */
function instanceOfPkiTidyCancelResponse(value) {
    return true;
}
function PkiTidyCancelResponseFromJSON(json) {
    return PkiTidyCancelResponseFromJSONTyped(json, false);
}
function PkiTidyCancelResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'acmeAccountDeletedCount': json['acme_account_deleted_count'] == null ? undefined : json['acme_account_deleted_count'],
        'acmeAccountRevokedCount': json['acme_account_revoked_count'] == null ? undefined : json['acme_account_revoked_count'],
        'acmeAccountSafetyBuffer': json['acme_account_safety_buffer'] == null ? undefined : json['acme_account_safety_buffer'],
        'acmeOrdersDeletedCount': json['acme_orders_deleted_count'] == null ? undefined : json['acme_orders_deleted_count'],
        'certMetadataDeletedCount': json['cert_metadata_deleted_count'] == null ? undefined : json['cert_metadata_deleted_count'],
        'certStoreDeletedCount': json['cert_store_deleted_count'] == null ? undefined : json['cert_store_deleted_count'],
        'cmpv2NonceDeletedCount': json['cmpv2_nonce_deleted_count'] == null ? undefined : json['cmpv2_nonce_deleted_count'],
        'crossRevokedCertDeletedCount': json['cross_revoked_cert_deleted_count'] == null ? undefined : json['cross_revoked_cert_deleted_count'],
        'currentCertStoreCount': json['current_cert_store_count'] == null ? undefined : json['current_cert_store_count'],
        'currentRevokedCertCount': json['current_revoked_cert_count'] == null ? undefined : json['current_revoked_cert_count'],
        'error': json['error'] == null ? undefined : json['error'],
        'internalBackendUuid': json['internal_backend_uuid'] == null ? undefined : json['internal_backend_uuid'],
        'issuerSafetyBuffer': json['issuer_safety_buffer'] == null ? undefined : json['issuer_safety_buffer'],
        'lastAutoTidyFinished': json['last_auto_tidy_finished'] == null ? undefined : json['last_auto_tidy_finished'],
        'message': json['message'] == null ? undefined : json['message'],
        'missingIssuerCertCount': json['missing_issuer_cert_count'] == null ? undefined : json['missing_issuer_cert_count'],
        'pauseDuration': json['pause_duration'] == null ? undefined : json['pause_duration'],
        'revocationQueueDeletedCount': json['revocation_queue_deleted_count'] == null ? undefined : json['revocation_queue_deleted_count'],
        'revocationQueueSafetyBuffer': json['revocation_queue_safety_buffer'] == null ? undefined : json['revocation_queue_safety_buffer'],
        'revokedCertDeletedCount': json['revoked_cert_deleted_count'] == null ? undefined : json['revoked_cert_deleted_count'],
        'safetyBuffer': json['safety_buffer'] == null ? undefined : json['safety_buffer'],
        'state': json['state'] == null ? undefined : json['state'],
        'tidyAcme': json['tidy_acme'] == null ? undefined : json['tidy_acme'],
        'tidyCertMetadata': json['tidy_cert_metadata'] == null ? undefined : json['tidy_cert_metadata'],
        'tidyCertStore': json['tidy_cert_store'] == null ? undefined : json['tidy_cert_store'],
        'tidyCmpv2NonceStore': json['tidy_cmpv2_nonce_store'] == null ? undefined : json['tidy_cmpv2_nonce_store'],
        'tidyCrossClusterRevokedCerts': json['tidy_cross_cluster_revoked_certs'] == null ? undefined : json['tidy_cross_cluster_revoked_certs'],
        'tidyExpiredIssuers': json['tidy_expired_issuers'] == null ? undefined : json['tidy_expired_issuers'],
        'tidyMoveLegacyCaBundle': json['tidy_move_legacy_ca_bundle'] == null ? undefined : json['tidy_move_legacy_ca_bundle'],
        'tidyRevocationQueue': json['tidy_revocation_queue'] == null ? undefined : json['tidy_revocation_queue'],
        'tidyRevokedCertIssuerAssociations': json['tidy_revoked_cert_issuer_associations'] == null ? undefined : json['tidy_revoked_cert_issuer_associations'],
        'tidyRevokedCerts': json['tidy_revoked_certs'] == null ? undefined : json['tidy_revoked_certs'],
        'timeFinished': json['time_finished'] == null ? undefined : json['time_finished'],
        'timeStarted': json['time_started'] == null ? undefined : json['time_started'],
        'totalAcmeAccountCount': json['total_acme_account_count'] == null ? undefined : json['total_acme_account_count'],
    };
}
function PkiTidyCancelResponseToJSON(json) {
    return PkiTidyCancelResponseToJSONTyped(json, false);
}
function PkiTidyCancelResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'acme_account_deleted_count': value['acmeAccountDeletedCount'],
        'acme_account_revoked_count': value['acmeAccountRevokedCount'],
        'acme_account_safety_buffer': value['acmeAccountSafetyBuffer'],
        'acme_orders_deleted_count': value['acmeOrdersDeletedCount'],
        'cert_metadata_deleted_count': value['certMetadataDeletedCount'],
        'cert_store_deleted_count': value['certStoreDeletedCount'],
        'cmpv2_nonce_deleted_count': value['cmpv2NonceDeletedCount'],
        'cross_revoked_cert_deleted_count': value['crossRevokedCertDeletedCount'],
        'current_cert_store_count': value['currentCertStoreCount'],
        'current_revoked_cert_count': value['currentRevokedCertCount'],
        'error': value['error'],
        'internal_backend_uuid': value['internalBackendUuid'],
        'issuer_safety_buffer': value['issuerSafetyBuffer'],
        'last_auto_tidy_finished': value['lastAutoTidyFinished'],
        'message': value['message'],
        'missing_issuer_cert_count': value['missingIssuerCertCount'],
        'pause_duration': value['pauseDuration'],
        'revocation_queue_deleted_count': value['revocationQueueDeletedCount'],
        'revocation_queue_safety_buffer': value['revocationQueueSafetyBuffer'],
        'revoked_cert_deleted_count': value['revokedCertDeletedCount'],
        'safety_buffer': value['safetyBuffer'],
        'state': value['state'],
        'tidy_acme': value['tidyAcme'],
        'tidy_cert_metadata': value['tidyCertMetadata'],
        'tidy_cert_store': value['tidyCertStore'],
        'tidy_cmpv2_nonce_store': value['tidyCmpv2NonceStore'],
        'tidy_cross_cluster_revoked_certs': value['tidyCrossClusterRevokedCerts'],
        'tidy_expired_issuers': value['tidyExpiredIssuers'],
        'tidy_move_legacy_ca_bundle': value['tidyMoveLegacyCaBundle'],
        'tidy_revocation_queue': value['tidyRevocationQueue'],
        'tidy_revoked_cert_issuer_associations': value['tidyRevokedCertIssuerAssociations'],
        'tidy_revoked_certs': value['tidyRevokedCerts'],
        'time_finished': value['timeFinished'],
        'time_started': value['timeStarted'],
        'total_acme_account_count': value['totalAcmeAccountCount'],
    };
}
