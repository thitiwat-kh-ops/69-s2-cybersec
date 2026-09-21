'use strict';

module.exports = {
  provider: 'console',
  name: 'Console',

  init: (providerOptions = {}, settings = {}) => {
    return {
      send: options => {
        options = options || {};
        options.from = options.from || settings.defaultFrom || 'no-reply@strapi.io';
        options.replyTo = options.replyTo || settings.defaultReplyTo || options.from;
        options.text = options.text || options.html;
        options.html = options.html || options.text;

        const maskSensitive = (value) => {
          if (typeof value !== 'string') return value;
          return value
            .replace(/[?&](?:code|token)=[^\s&]+/gi, (m) => m.replace(/=([^\s&]+)$/, '=[REDACTED]'))
            .replace(/\b\d{6}\b/g, '******');
        };

        strapi.log.debug(
          `SendEmail mock:\n\tto: ${options.to}\n\tfrom: ${options.from}\n\tsubject: ${options.subject}\n\ttext: ${maskSensitive(options.text || options.html)}`
        );

        return Promise.resolve();
      },
    };
  },
};