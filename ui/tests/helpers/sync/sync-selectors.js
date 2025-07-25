/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import { click, fillIn } from '@ember/test-helpers';
import { GENERAL } from 'vault/tests/helpers/general-selectors';

export const PAGE = {
  ...GENERAL,
  cta: {
    summary: '[data-test-cta-container] p',
    link: '[data-test-cta-doc-link]',
    button: '[data-test-cta-button]',
  },
  associations: {
    list: {
      name: '[data-test-association-name]',
      status: '[data-test-association-status]',
      updated: '[data-test-association-updated]',
      refresh: '[data-test-refresh-list]',
      menu: {
        sync: '[data-test-association-action="sync"]',
        view: '[data-test-association-action="view"]',
        unsync: '[data-test-association-action="unsync"]',
      },
    },
  },
  destinations: {
    deleteBanner: '[data-test-delete-status-banner]',
    details: {
      sectionHeader: '[data-test-section-header]',
    },
    sync: {
      mountSelect: '[data-test-sync-mount-select]',
      mountInput: '[data-test-sync-mount-input]',
      successMessage: '[data-test-sync-success-message]',
    },
    list: {
      icon: '[data-test-destination-icon]',
      name: '[data-test-destination-name]',
      type: '[data-test-destination-type]',
      deleteAction: '[data-test-delete]',
      create: '[data-test-create-destination]',
      menu: {
        details: '[data-test-details]',
        edit: '[data-test-edit]',
      },
    },
  },
  overview: {
    optInBanner: {
      container: '[data-test-secrets-sync-opt-in-banner]',
      enable: '[data-test-secrets-sync-opt-in-banner-enable]',
      description: '[data-test-secrets-sync-opt-in-banner-description]',
      dismiss: '[data-test-secrets-sync-opt-in-banner] [data-test-icon="x"]',
    },
    activationModal: {
      container: '[data-test-secrets-sync-opt-in-modal]',
      checkbox: '[data-test-opt-in-check]',
      confirm: '[data-test-opt-in-confirm]',
      cancel: '[data-test-opt-in-cancel]',
    },
    optInError: '[data-test-opt-in-error]',
    createDestination: '[data-test-create-destination]',
    table: {
      row: '[data-test-overview-table-row]',
      icon: (index) => `[data-test-overview-table-icon="${index}"]`,
      name: (index) => `[data-test-overview-table-name="${index}"]`,
      badge: (index) => `[data-test-overview-table-badge="${index}"]`,
      total: (index) => `[data-test-overview-table-total="${index}"]`,
      updated: (index) => `[data-test-overview-table-updated="${index}"]`,
      actionToggle: (index) => `[data-test-overview-table-action-toggle="${index}"]`,
      action: (name) => `[data-test-overview-table-action="${name}"]`,
    },
  },
  badgeText: {
    icon: (name) => `[data-test-icon="${name}"]`,
    text: '.hds-badge__text',
  },
  selectType: (type) => `[data-test-select-destination="${type}"]`,
  createCancel: '[data-test-destination-create-cancel]',
  toolbar: (btnText) => `[data-test-toolbar="${btnText}"]`,
  form: {
    enableInput: (attr) => `[data-test-enable-field="${attr}"] [data-test-icon="edit"]`, // TODO duplicated in general-selectors as this component became more widely used
    fieldGroupHeader: (group) => `[data-test-destination-header="${group}"]`,
    fieldGroupSubtext: (group) => `[data-test-destination-subText="${group}"]`,
    fillInByAttr: async (attr, value) => {
      // for handling more complex form input elements by attr name
      switch (attr) {
        case 'granularity':
          return await click(`${GENERAL.radioByAttr('secret-key')}`);
        case 'credentials':
          await click(GENERAL.textToggle);
          return fillIn(GENERAL.maskedInput, value);
        case 'custom_tags':
          await fillIn('[data-test-kv-key="0"]', 'foo');
          return fillIn('[data-test-kv-value="0"]', value);
        case 'deployment_environments':
          await click(`${GENERAL.inputGroupByAttr('deployment_environments')} input#development`);
          await click(`${GENERAL.inputGroupByAttr('deployment_environments')} input#preview`);
          return await click(`${GENERAL.inputGroupByAttr('deployment_environments')} input#production`);
        default:
          return fillIn(`[data-test-input="${attr}"]`, value);
      }
    },
  },
};
