'use strict';

const bcrypt = require('bcryptjs');
const _ = require('lodash');
const { getAbsoluteAdminUrl } = require('@strapi/utils');
const { ApplicationError } = require('@strapi/utils').errors;
const { getService } = require('../utils');

const { sha256, tokenData, tokenValid } = require('audit-log');

/**
 * hashes a password
 * @param {string} password - password to hash
 * @returns {string} hashed password
 */
const hashPassword = (password) => bcrypt.hash(password, 10);

/**
 * Validate a password
 * @param {string} password
 * @param {string} hash
 * @returns {Promise<boolean>} is the password valid
 */
const validatePassword = (password, hash) => bcrypt.compare(password, hash);

/**
 * Check login credentials
 * @param {Object} options
 * @param {string} options.email
 * @param {string} options.password
 */
const checkCredentials = async ({ email, password }) => {
  const user = await strapi.query('admin::user').findOne({ where: { email } });

  if (!user || !user.password) {
    return [null, false, { message: 'Invalid credentials' }];
  }

  const isValid = await validatePassword(password, user.password);

  if (!isValid) {
    return [null, false, { message: 'Invalid credentials' }];
  }

  if (!(user.isActive === true)) {
    return [null, false, { message: 'User not active' }];
  }

  return [null, user];
};

/**
 * Send an email to the user if it exists or do nothing
 * @param {Object} param params
 * @param {string} param.email user email for which to reset the password
 */
const forgotPassword = async ({ email } = {}) => {
  const user = await strapi.query('admin::user').findOne({ where: { email, isActive: true } });

  if (!user) {
    return;
  }

  // Au4/Ac11: store token HASHED with TTL, never the plaintext.
  const { plain: resetPasswordToken, stored } = tokenData();
  await getService('user').updateById(user.id, { resetPasswordToken: stored });

  // Send an email to the admin.
  const url = `${getAbsoluteAdminUrl(
    strapi.config
  )}/auth/reset-password?code=${resetPasswordToken}`;
  return strapi
    .plugin('email')
    .service('email')
    .sendTemplatedEmail(
      {
        to: user.email,
        from: strapi.config.get('admin.forgotPassword.from'),
        replyTo: strapi.config.get('admin.forgotPassword.replyTo'),
      },
      strapi.config.get('admin.forgotPassword.emailTemplate'),
      {
        url,
        user: _.pick(user, ['email', 'firstname', 'lastname', 'username']),
      }
    )
    .catch((err) => {
      // log error server side but do not disclose it to the user to avoid leaking informations
      strapi.log.error(err);
    });
};

/**
 * Reset a user password
 * @param {Object} param params
 * @param {string} param.resetPasswordToken token generated to request a password reset
 * @param {string} param.password new user password
 */
const resetPassword = async ({ resetPasswordToken, password } = {}) => {
  if (!resetPasswordToken) {
    throw new ApplicationError();
  }
  const hashPrefix = sha256(resetPasswordToken) + ':';
  const matchingUser = await strapi
    .query('admin::user')
    .findOne({ where: { resetPasswordToken: { $startsWith: hashPrefix }, isActive: true } });

  if (!matchingUser || !tokenValid(matchingUser.resetPasswordToken, resetPasswordToken)) {
    throw new ApplicationError();
  }

  return getService('user').updateById(matchingUser.id, {
    password,
    resetPasswordToken: null,
  });
};

module.exports = {
  checkCredentials,
  validatePassword,
  hashPassword,
  forgotPassword,
  resetPassword,
};