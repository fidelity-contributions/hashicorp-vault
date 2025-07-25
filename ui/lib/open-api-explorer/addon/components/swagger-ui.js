/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import Component from '@glimmer/component';
import { service } from '@ember/service';
import { action } from '@ember/object';
import { tracked } from '@glimmer/tracking';
import parseURL from 'core/utils/parse-url';
import config from 'vault/config/environment';
import openApiExplorerConfig from 'open-api-explorer/config/environment';
import { guidFor } from '@ember/object/internals';
import SwaggerUIBundle from 'swagger-ui-dist/swagger-ui-bundle.js';
import { camelize } from '@ember/string';
import keys from 'core/utils/keys';

const { APP } = openApiExplorerConfig;

export default class SwaggerUiComponent extends Component {
  @service auth;
  @service namespace;

  @tracked swaggerLoading = true;

  inputId = `${guidFor(this)}-swagger`;

  SearchFilterPlugin() {
    return {
      fn: {
        opsFilter: (taggedOps, phrase) => {
          const filteredOperations = taggedOps.reduce((acc, tagObj) => {
            const operations = tagObj.get('operations');

            // filter out operations where the path doesn't match search phrase
            const operationsWithMatchingPath = operations.filter((operationObj) => {
              const path = operationObj.get('path');
              return path.includes(phrase);
            });

            // if there are any operations left after filtering, add the tagObj to the accumulator
            if (operationsWithMatchingPath.size > 0) {
              acc.push(tagObj.set('operations', operationsWithMatchingPath));
            }

            return acc;
          }, []);

          return filteredOperations;
        },
      },
    };
  }

  // the operationId values in the spec are dasherized
  // camelize the values so they match the function names in the generated API client SDK
  CamelizeOperationIdPlugin() {
    return {
      wrapComponents: {
        operation:
          (Original, { React }) =>
          (props) => {
            const { operation } = props;
            const operationId = operation.get('operationId');

            if (operationId) {
              return React.createElement(Original, {
                ...props,
                operation: operation.set('operationId', camelize(operationId)),
              });
            }

            return React.createElement(Original, props);
          },
      },
    };
  }

  CONFIG = (SwaggerUIBundle, componentInstance) => {
    return {
      dom_id: `#${componentInstance.inputId}`,
      url: '/v1/sys/internal/specs/openapi',
      deepLinking: false,
      presets: [SwaggerUIBundle.presets.apis],
      plugins: [SwaggerUIBundle.plugins.DownloadUrl, this.SearchFilterPlugin, this.CamelizeOperationIdPlugin],
      // 'list' expands tags, but not operations
      docExpansion: 'list',
      operationsSorter: 'alpha',
      displayOperationId: config.environment === 'development',
      filter: true,
      // this makes sure we show the x-vault- options
      showExtensions: true,
      // we don't have any models defined currently
      defaultModelsExpandDepth: -1,
      defaultModelExpandDepth: 1,
      requestInterceptor: (req) => {
        // we need to add vault authorization header
        // and namespace headers for things to work properly
        req.headers['X-Vault-Token'] = componentInstance.auth.currentToken;
        const namespace = componentInstance.namespace.path;
        if (namespace && !APP.NAMESPACE_ROOT_URLS.some((str) => req.url.includes(str))) {
          req.headers['X-Vault-Namespace'] = namespace;
        }
        // we want to link to the right JSON in swagger UI so
        // it's already been pre-pended
        if (!req.loadSpec) {
          const { protocol, host, pathname, search } = parseURL(req.url);
          //paths in the spec don't have /v1 in them, so we need to add that here
          //           http(s):  vlt.io:4200  /sys/mounts
          req.url = `${protocol}//${host}/v1${pathname}${search}`;
        }
        return req;
      },
      onComplete: () => {
        componentInstance.swaggerLoading = false;
        this.applyA11yFixes();
      },
    };
  };

  // using an action to bind the correct "this" context
  @action async swaggerInit() {
    const configSettings = this.CONFIG(SwaggerUIBundle, this);
    SwaggerUIBundle(configSettings);
  }

  applyA11yFixes() {
    const container = document.querySelector('.swagger-ui');
    if (container) {
      this.observer = new MutationObserver(() => {
        this.updateCaretTabIndex();
        this.updateCopyToClipboard();
        this.updateDisabledFields();
        this.updateTryItOutButtonDescription();
      });
      this.observer.observe(container, { childList: true, subtree: true });
      // Run once on initial load
      this.updateCaretTabIndex();
      this.updateCopyToClipboard();
      this.updateDisabledFields();
      this.updateTryItOutButtonDescription();
    }
  }

  updateCaretTabIndex() {
    document.querySelectorAll('.opblock-control-arrow').forEach((el) => {
      el.tabIndex = 0;
    });
  }

  updateCopyToClipboard() {
    document.querySelectorAll('.copy-to-clipboard').forEach((div) => {
      div.tabIndex = 0;
      div.setAttribute('role', 'button');
      div.addEventListener('keydown', function (e) {
        if (e.key === keys.ENTER || e.key === keys.SPACE) {
          const svg = div.querySelector('svg');
          if (svg) {
            svg.dispatchEvent(new MouseEvent('click', { bubbles: true }));
          }
          e.preventDefault();
        }
      });
    });
  }

  updateDisabledFields() {
    document.querySelectorAll('.parameters :disabled').forEach((el) => {
      el.removeAttribute('disabled');
      el.setAttribute('readonly', true);
    });
  }

  updateTryItOutButtonDescription() {
    document.querySelectorAll('.try-out button').forEach((el) => {
      const warning =
        'Caution: This will make requests to the Vault server on your behalf which may create or delete items.';

      el.setAttribute('aria-description', warning);
    });
  }

  willDestroy() {
    this.observer.disconnect();
    super.willDestroy();
  }
}
