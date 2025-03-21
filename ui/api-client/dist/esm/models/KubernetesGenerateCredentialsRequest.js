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
 * Check if a given object implements the KubernetesGenerateCredentialsRequest interface.
 */
export function instanceOfKubernetesGenerateCredentialsRequest(value) {
    if (!('kubernetesNamespace' in value) || value['kubernetesNamespace'] === undefined)
        return false;
    return true;
}
export function KubernetesGenerateCredentialsRequestFromJSON(json) {
    return KubernetesGenerateCredentialsRequestFromJSONTyped(json, false);
}
export function KubernetesGenerateCredentialsRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'audiences': json['audiences'] == null ? undefined : json['audiences'],
        'clusterRoleBinding': json['cluster_role_binding'] == null ? undefined : json['cluster_role_binding'],
        'kubernetesNamespace': json['kubernetes_namespace'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
    };
}
export function KubernetesGenerateCredentialsRequestToJSON(json) {
    return KubernetesGenerateCredentialsRequestToJSONTyped(json, false);
}
export function KubernetesGenerateCredentialsRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'audiences': value['audiences'],
        'cluster_role_binding': value['clusterRoleBinding'],
        'kubernetes_namespace': value['kubernetesNamespace'],
        'ttl': value['ttl'],
    };
}
