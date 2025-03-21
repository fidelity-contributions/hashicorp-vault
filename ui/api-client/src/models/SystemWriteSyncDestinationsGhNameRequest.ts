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

import { mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface SystemWriteSyncDestinationsGhNameRequest
 */
export interface SystemWriteSyncDestinationsGhNameRequest {
    /**
     * Classic or fine-grained access token to access your GitHub organization.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    accessToken?: string;
    /**
     * Sets which IPv4 addresses Vault is allowed to connect to for syncing secrets.
     * @type {Array<string>}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    allowedIpv4Addresses?: Array<string>;
    /**
     * Sets which IPv6 addresses Vault is allowed to connect to for syncing secrets.
     * @type {Array<string>}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    allowedIpv6Addresses?: Array<string>;
    /**
     * Sets which port numbers Vault is allowed to connect through for syncing secrets.
     * @type {Array<string>}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    allowedPorts?: Array<string>;
    /**
     * The user defined name of the GitHub App configuration.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    appName?: string;
    /**
     * Allows all IP addresses and ports to be connected to for syncing secrets.
     * @type {boolean}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    disableStrictNetworking?: boolean;
    /**
     * The name of the repository environment that the secrets in GitHub will be available for. Only valid when the 'secrets_location' field is set to 'repository'.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    environmentName?: string;
    /**
     * Determines what level of information is synced as a distinct resource at the destination. Supports `secret-path` and `secret-key`.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    granularity?: string;
    /**
     * The ID of the GitHub App installation, returned by GitHub after installing the app on your repository
     * @type {number}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    installationId?: number;
    /**
     * The name of the GitHub organization to target which owns the repositories the secrets will be available for. Only valid when 'secrets_location' is set to 'organization'.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    organizationName?: string;
    /**
     * The type of repositories in a GitHub organization to grant visibility to the secrets, between 'all', 'private', or 'selected'. If using 'selected', you must also specify the 'selected_repository_names' field. Only valid when 'secrets_location' is set to 'organization'.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    organizationVisibility?: string;
    /**
     * Asynchronously unsyncs all associated secrets with the destination then deletes the destination config.
     * @type {boolean}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    purge?: boolean;
    /**
     * Name of the repository where to manage secrets. For example for 'git clone github.com/acme/my-repo' the name is my-repo.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    repositoryName?: string;
    /**
     * Organization name or username the repository belongs to. For example for 'git clone github.com/acme/my-repo' the owner is acme.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    repositoryOwner?: string;
    /**
     * Template describing how to generate external secret names. Supports a subset of the Go Template syntax.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    secretNameTemplate?: string;
    /**
     * The scope of access that the secrets in GitHub will be available for, between 'organization' or 'repository'. Repository secrets are only visible on the given repository while Organization secrets are visible to as many repositories within the organization as determined by the 'organization_visibility' field. Defaults to 'repository'.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    secretsLocation?: string;
    /**
     * The list of names of all repositories within a GitHub organization to grant access to the secrets when 'organization_visibility' is set to 'selected'.
     * @type {Array<string>}
     * @memberof SystemWriteSyncDestinationsGhNameRequest
     */
    selectedRepositoryNames?: Array<string>;
}

/**
 * Check if a given object implements the SystemWriteSyncDestinationsGhNameRequest interface.
 */
export function instanceOfSystemWriteSyncDestinationsGhNameRequest(value: object): value is SystemWriteSyncDestinationsGhNameRequest {
    return true;
}

export function SystemWriteSyncDestinationsGhNameRequestFromJSON(json: any): SystemWriteSyncDestinationsGhNameRequest {
    return SystemWriteSyncDestinationsGhNameRequestFromJSONTyped(json, false);
}

export function SystemWriteSyncDestinationsGhNameRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): SystemWriteSyncDestinationsGhNameRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'accessToken': json['access_token'] == null ? undefined : json['access_token'],
        'allowedIpv4Addresses': json['allowed_ipv4_addresses'] == null ? undefined : json['allowed_ipv4_addresses'],
        'allowedIpv6Addresses': json['allowed_ipv6_addresses'] == null ? undefined : json['allowed_ipv6_addresses'],
        'allowedPorts': json['allowed_ports'] == null ? undefined : json['allowed_ports'],
        'appName': json['app_name'] == null ? undefined : json['app_name'],
        'disableStrictNetworking': json['disable_strict_networking'] == null ? undefined : json['disable_strict_networking'],
        'environmentName': json['environment_name'] == null ? undefined : json['environment_name'],
        'granularity': json['granularity'] == null ? undefined : json['granularity'],
        'installationId': json['installation_id'] == null ? undefined : json['installation_id'],
        'organizationName': json['organization_name'] == null ? undefined : json['organization_name'],
        'organizationVisibility': json['organization_visibility'] == null ? undefined : json['organization_visibility'],
        'purge': json['purge'] == null ? undefined : json['purge'],
        'repositoryName': json['repository_name'] == null ? undefined : json['repository_name'],
        'repositoryOwner': json['repository_owner'] == null ? undefined : json['repository_owner'],
        'secretNameTemplate': json['secret_name_template'] == null ? undefined : json['secret_name_template'],
        'secretsLocation': json['secrets_location'] == null ? undefined : json['secrets_location'],
        'selectedRepositoryNames': json['selected_repository_names'] == null ? undefined : json['selected_repository_names'],
    };
}

export function SystemWriteSyncDestinationsGhNameRequestToJSON(json: any): SystemWriteSyncDestinationsGhNameRequest {
    return SystemWriteSyncDestinationsGhNameRequestToJSONTyped(json, false);
}

export function SystemWriteSyncDestinationsGhNameRequestToJSONTyped(value?: SystemWriteSyncDestinationsGhNameRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'access_token': value['accessToken'],
        'allowed_ipv4_addresses': value['allowedIpv4Addresses'],
        'allowed_ipv6_addresses': value['allowedIpv6Addresses'],
        'allowed_ports': value['allowedPorts'],
        'app_name': value['appName'],
        'disable_strict_networking': value['disableStrictNetworking'],
        'environment_name': value['environmentName'],
        'granularity': value['granularity'],
        'installation_id': value['installationId'],
        'organization_name': value['organizationName'],
        'organization_visibility': value['organizationVisibility'],
        'purge': value['purge'],
        'repository_name': value['repositoryName'],
        'repository_owner': value['repositoryOwner'],
        'secret_name_template': value['secretNameTemplate'],
        'secrets_location': value['secretsLocation'],
        'selected_repository_names': value['selectedRepositoryNames'],
    };
}

