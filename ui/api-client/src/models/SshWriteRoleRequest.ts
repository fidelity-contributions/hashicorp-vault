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
 * @interface SshWriteRoleRequest
 */
export interface SshWriteRoleRequest {
    /**
     * [Not applicable for OTP type] [Optional for CA type] When supplied, this value specifies a signing algorithm for the key. Possible values: ssh-rsa, rsa-sha2-256, rsa-sha2-512, default, or the empty string.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    algorithmSigner?: SshWriteRoleRequestAlgorithmSignerEnum;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, host certificates that are requested are allowed to use the base domains listed in "allowed_domains", e.g. "example.com". This is a separate option as in some cases this can be considered a security threat.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    allowBareDomains?: boolean;
    /**
     * Whether to allow issuing certificates with no valid principals (meaning any valid principal). Exists for backwards compatibility only, the default of false is highly recommended.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    allowEmptyPrincipals?: boolean;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, certificates are allowed to be signed for use as a 'host'.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    allowHostCertificates?: boolean;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, host certificates that are requested are allowed to use subdomains of those listed in "allowed_domains".
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    allowSubdomains?: boolean;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, certificates are allowed to be signed for use as a 'user'.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    allowUserCertificates?: boolean;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If true, users can override the key ID for a signed certificate with the "key_id" field. When false, the key ID will always be the token display name. The key ID is logged by the SSH server and can be useful for auditing.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    allowUserKeyIds?: boolean;
    /**
     * [Not applicable for OTP type] [Optional for CA type] A comma-separated list of critical options that certificates can have when signed. To allow any critical options, set this to an empty string.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    allowedCriticalOptions?: string;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If this option is not specified, client can request for a signed certificate for any valid host. If only certain domains are allowed, then this list enforces it.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    allowedDomains?: string;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, Allowed domains can be specified using identity template policies. Non-templated domains are also permitted.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    allowedDomainsTemplate?: boolean;
    /**
     * [Not applicable for OTP type] [Optional for CA type] A comma-separated list of extensions that certificates can have when signed. An empty list means that no extension overrides are allowed by an end-user; explicitly specify '*' to allow any extensions to be set.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    allowedExtensions?: string;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, allows the enforcement of key types and minimum key sizes to be signed.
     * @type {object}
     * @memberof SshWriteRoleRequest
     */
    allowedUserKeyLengths?: object;
    /**
     * [Optional for all types] [Works differently for CA type] If this option is not specified, or is '*', client can request a credential for any valid user at the remote host, including the admin user. If only certain usernames are to be allowed, then this list enforces it. If this field is set, then credentials can only be created for default_user and usernames present in this list. Setting this option will enable all the users with access to this role to fetch credentials for all other usernames in this list. Use with caution. N.B.: with the CA type, an empty list means that no users are allowed; explicitly specify '*' to allow any user.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    allowedUsers?: string;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, Allowed users can be specified using identity template policies. Non-templated users are also permitted.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    allowedUsersTemplate?: boolean;
    /**
     * [Optional for OTP type] [Not applicable for CA type] Comma separated list of CIDR blocks for which the role is applicable for. CIDR blocks can belong to more than one role.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    cidrList?: string;
    /**
     * [Not applicable for OTP type] [Optional for CA type] Critical options certificates should have if none are provided when signing. This field takes in key value pairs in JSON format. Note that these are not restricted by "allowed_critical_options". Defaults to none.
     * @type {object}
     * @memberof SshWriteRoleRequest
     */
    defaultCriticalOptions?: object;
    /**
     * [Not applicable for OTP type] [Optional for CA type] Extensions certificates should have if none are provided when signing. This field takes in key value pairs in JSON format. Note that these are not restricted by "allowed_extensions". Defaults to none.
     * @type {object}
     * @memberof SshWriteRoleRequest
     */
    defaultExtensions?: object;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, Default extension values can be specified using identity template policies. Non-templated extension values are also permitted.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    defaultExtensionsTemplate?: boolean;
    /**
     * [Required for OTP type] [Optional for CA type] Default username for which a credential will be generated. When the endpoint 'creds/' is used without a username, this value will be used as default username.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    defaultUser?: string;
    /**
     * [Not applicable for OTP type] [Optional for CA type] If set, Default user can be specified using identity template policies. Non-templated users are also permitted.
     * @type {boolean}
     * @memberof SshWriteRoleRequest
     */
    defaultUserTemplate?: boolean;
    /**
     * [Optional for OTP type] [Not applicable for CA type] Comma separated list of CIDR blocks. IP addresses belonging to these blocks are not accepted by the role. This is particularly useful when big CIDR blocks are being used by the role and certain parts of it needs to be kept out.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    excludeCidrList?: string;
    /**
     * [Not applicable for OTP type] [Optional for CA type] When supplied, this value specifies a custom format for the key id of a signed certificate. The following variables are available for use: '{{token_display_name}}' - The display name of the token used to make the request. '{{role_name}}' - The name of the role signing the request. '{{public_key_hash}}' - A SHA256 checksum of the public key that is being signed.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    keyIdFormat?: string;
    /**
     * [Required for all types] Type of key used to login to hosts. It can be either 'otp' or 'ca'. 'otp' type requires agent to be installed in remote hosts.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    keyType?: SshWriteRoleRequestKeyTypeEnum;
    /**
     * [Not applicable for OTP type] [Optional for CA type] The maximum allowed lease duration
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    maxTtl?: string;
    /**
     * [Not applicable for OTP type] [Optional for CA type] The duration that the SSH certificate should be backdated by at issuance.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    notBeforeDuration?: string;
    /**
     * [Optional for OTP type] [Not applicable for CA type] Port number for SSH connection. Default is '22'. Port number does not play any role in creation of OTP. For 'otp' type, this is just a way to inform client about the port number to use. Port number will be returned to client by Vault server along with OTP.
     * @type {number}
     * @memberof SshWriteRoleRequest
     */
    port?: number;
    /**
     * [Not applicable for OTP type] [Optional for CA type] The lease duration if no specific lease duration is requested. The lease duration controls the expiration of certificates issued by this backend. Defaults to the value of max_ttl.
     * @type {string}
     * @memberof SshWriteRoleRequest
     */
    ttl?: string;
}

/**
* @export
* @enum {string}
*/
export enum SshWriteRoleRequestAlgorithmSignerEnum {
    EMPTY = '',
    DEFAULT = 'default',
    SSH_RSA = 'ssh-rsa',
    RSA_SHA2_256 = 'rsa-sha2-256',
    RSA_SHA2_512 = 'rsa-sha2-512'
}
/**
* @export
* @enum {string}
*/
export enum SshWriteRoleRequestKeyTypeEnum {
    OTP = 'otp',
    CA = 'ca'
}


/**
 * Check if a given object implements the SshWriteRoleRequest interface.
 */
export function instanceOfSshWriteRoleRequest(value: object): value is SshWriteRoleRequest {
    return true;
}

export function SshWriteRoleRequestFromJSON(json: any): SshWriteRoleRequest {
    return SshWriteRoleRequestFromJSONTyped(json, false);
}

export function SshWriteRoleRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): SshWriteRoleRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'algorithmSigner': json['algorithm_signer'] == null ? undefined : json['algorithm_signer'],
        'allowBareDomains': json['allow_bare_domains'] == null ? undefined : json['allow_bare_domains'],
        'allowEmptyPrincipals': json['allow_empty_principals'] == null ? undefined : json['allow_empty_principals'],
        'allowHostCertificates': json['allow_host_certificates'] == null ? undefined : json['allow_host_certificates'],
        'allowSubdomains': json['allow_subdomains'] == null ? undefined : json['allow_subdomains'],
        'allowUserCertificates': json['allow_user_certificates'] == null ? undefined : json['allow_user_certificates'],
        'allowUserKeyIds': json['allow_user_key_ids'] == null ? undefined : json['allow_user_key_ids'],
        'allowedCriticalOptions': json['allowed_critical_options'] == null ? undefined : json['allowed_critical_options'],
        'allowedDomains': json['allowed_domains'] == null ? undefined : json['allowed_domains'],
        'allowedDomainsTemplate': json['allowed_domains_template'] == null ? undefined : json['allowed_domains_template'],
        'allowedExtensions': json['allowed_extensions'] == null ? undefined : json['allowed_extensions'],
        'allowedUserKeyLengths': json['allowed_user_key_lengths'] == null ? undefined : json['allowed_user_key_lengths'],
        'allowedUsers': json['allowed_users'] == null ? undefined : json['allowed_users'],
        'allowedUsersTemplate': json['allowed_users_template'] == null ? undefined : json['allowed_users_template'],
        'cidrList': json['cidr_list'] == null ? undefined : json['cidr_list'],
        'defaultCriticalOptions': json['default_critical_options'] == null ? undefined : json['default_critical_options'],
        'defaultExtensions': json['default_extensions'] == null ? undefined : json['default_extensions'],
        'defaultExtensionsTemplate': json['default_extensions_template'] == null ? undefined : json['default_extensions_template'],
        'defaultUser': json['default_user'] == null ? undefined : json['default_user'],
        'defaultUserTemplate': json['default_user_template'] == null ? undefined : json['default_user_template'],
        'excludeCidrList': json['exclude_cidr_list'] == null ? undefined : json['exclude_cidr_list'],
        'keyIdFormat': json['key_id_format'] == null ? undefined : json['key_id_format'],
        'keyType': json['key_type'] == null ? undefined : json['key_type'],
        'maxTtl': json['max_ttl'] == null ? undefined : json['max_ttl'],
        'notBeforeDuration': json['not_before_duration'] == null ? undefined : json['not_before_duration'],
        'port': json['port'] == null ? undefined : json['port'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
    };
}

export function SshWriteRoleRequestToJSON(json: any): SshWriteRoleRequest {
    return SshWriteRoleRequestToJSONTyped(json, false);
}

export function SshWriteRoleRequestToJSONTyped(value?: SshWriteRoleRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'algorithm_signer': value['algorithmSigner'],
        'allow_bare_domains': value['allowBareDomains'],
        'allow_empty_principals': value['allowEmptyPrincipals'],
        'allow_host_certificates': value['allowHostCertificates'],
        'allow_subdomains': value['allowSubdomains'],
        'allow_user_certificates': value['allowUserCertificates'],
        'allow_user_key_ids': value['allowUserKeyIds'],
        'allowed_critical_options': value['allowedCriticalOptions'],
        'allowed_domains': value['allowedDomains'],
        'allowed_domains_template': value['allowedDomainsTemplate'],
        'allowed_extensions': value['allowedExtensions'],
        'allowed_user_key_lengths': value['allowedUserKeyLengths'],
        'allowed_users': value['allowedUsers'],
        'allowed_users_template': value['allowedUsersTemplate'],
        'cidr_list': value['cidrList'],
        'default_critical_options': value['defaultCriticalOptions'],
        'default_extensions': value['defaultExtensions'],
        'default_extensions_template': value['defaultExtensionsTemplate'],
        'default_user': value['defaultUser'],
        'default_user_template': value['defaultUserTemplate'],
        'exclude_cidr_list': value['excludeCidrList'],
        'key_id_format': value['keyIdFormat'],
        'key_type': value['keyType'],
        'max_ttl': value['maxTtl'],
        'not_before_duration': value['notBeforeDuration'],
        'port': value['port'],
        'ttl': value['ttl'],
    };
}

