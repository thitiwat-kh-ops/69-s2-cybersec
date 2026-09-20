'use strict';

const crypto = require('crypto');
const _ = require('lodash');
const { concat, compact, isArray } = require('lodash/fp');
const utils = require('@strapi/utils');
const {
  contentTypes: { getNonWritableAttributes },
} = require('@strapi/utils');
const { getService } = require('../utils');
const {
  validateCallbackBody,
  validateRegisterBody,
  validateSendEmailConfirmationBody,
  validateForgotPasswordBody,
  validateResetPasswordBody,
  validateEmailConfirmationBody,
  validateChangePasswordBody,
} = require('./validation/auth');

const { getAbsoluteAdminUrl, getAbsoluteServerUrl, sanitize } = utils;
const { ApplicationError, ValidationError, ForbiddenError } = utils.errors;

const {
  sha256,
  tokenData,
  tokenValid,
  checkPasswordPolicy,
  audit,
} = require('audit-log');

const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel('plugin::users-permissions.user');

  return sanitize.contentAPI.output(user, userSchema, { auth });
};

const auditCtx = (ctx, extra) =>
  audit({
    ip: (ctx.request && ctx.request.ip) || null,
    userAgent: (ctx.request && ctx.request.headers && ctx.request.headers['user-agent']) || null,
    ...extra,
  });

const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const newRefreshToken = async (userId) => {
  const plain = crypto.randomBytes(48).toString('hex');
  const conn = strapi.db.connection('refresh_tokens');
  await conn.where({ user_id: userId }).del();
  await conn.insert({
    user_id: userId,
    token_hash: sha256(plain),
    expires_at: Date.now() + REFRESH_TTL_MS,
  });
  return plain;
};

const findUserByRefreshToken = async (plain) => {
  if (!plain) return null;
  const [row] = await strapi.db
    .connection('refresh_tokens')
    .where('token_hash', sha256(plain))
    .andWhere('expires_at', '>', Date.now())
    .select('user_id')
    .limit(1);
  if (!row) return null;
  return strapi.query('plugin::users-permissions.user').findOne({ where: { id: row.user_id } });
};

const getEmailSettings = async () => {
  const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });
  return {
    email: await pluginStore.get({ key: 'email' }),
    advanced: await pluginStore.get({ key: 'advanced' }),
  };
};

const sendEmail = async ({ to, subject, text, html }) => {
  if (!to) return;
  const emailObj = {
    to,
    from: undefined,
    replyTo: undefined,
    subject,
    text,
    html: html || text,
  };
  const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });
  const emailSettings = (await pluginStore.get({ key: 'email' })) || {};
  const from = _.get(emailSettings, 'reset_password.options.from', null);
  if (from && from.email) {
    emailObj.from = from.name ? `${from.name} <${from.email}>` : from.email;
  }
  await strapi.plugin('email').service('email').send(emailObj);
};

module.exports = {
  async callback(ctx) {
    const provider = ctx.params.provider || 'local';
    const params = ctx.request.body;

    const store = strapi.store({ type: 'plugin', name: 'users-permissions' });
    const grantSettings = await store.get({ key: 'grant' });

    const grantProvider = provider === 'local' ? 'email' : provider;

    if (!_.get(grantSettings, [grantProvider, 'enabled'])) {
      throw new ApplicationError('This provider is disabled');
    }

    if (provider === 'local') {
      await validateCallbackBody(params);

      const { identifier } = params;

      // Check if the user exists.
      const user = await strapi.query('plugin::users-permissions.user').findOne({
        where: {
          provider,
          $or: [{ email: identifier.toLowerCase() }, { username: identifier }],
        },
      });

      if (!user) {
        auditCtx(ctx, { action: 'user_login', email: identifier.toLowerCase(), result: 'failed' });
        throw new ValidationError('Invalid identifier or password');
      }

      if (!user.password) {
        auditCtx(ctx, { action: 'user_login', email: user.email, result: 'failed' });
        throw new ValidationError('Invalid identifier or password');
      }

      const validPassword = await getService('user').validatePassword(
        params.password,
        user.password
      );

      if (!validPassword) {
        auditCtx(ctx, { action: 'user_login', email: user.email, result: 'failed' });
        throw new ValidationError('Invalid identifier or password');
      }

      const advancedSettings = await store.get({ key: 'advanced' });
      const requiresConfirmation = _.get(advancedSettings, 'email_confirmation');

      if (requiresConfirmation && user.confirmed !== true) {
        auditCtx(ctx, { action: 'user_login', email: user.email, result: 'failed' });
        throw new ApplicationError('Your account email is not confirmed');
      }

      if (user.blocked === true) {
        auditCtx(ctx, { action: 'user_login', email: user.email, result: 'failed' });
        throw new ApplicationError('Your account has been blocked by an administrator');
      }

      const refreshToken = await newRefreshToken(user.id);
      auditCtx(ctx, { action: 'user_login', email: user.email, result: 'success' });

      return ctx.send({
        jwt: getService('jwt').issue({ id: user.id }),
        refreshToken,
        user: await sanitizeUser(user, ctx),
      });
    }

    // Connect the user with the third-party provider.
    try {
      const user = await getService('providers').connect(provider, ctx.query);

      if (user.blocked) {
        throw new ForbiddenError('Your account has been blocked by an administrator');
      }

      const refreshToken = await newRefreshToken(user.id);

      return ctx.send({
        jwt: getService('jwt').issue({ id: user.id }),
        refreshToken,
        user: await sanitizeUser(user, ctx),
      });
    } catch (error) {
      throw new ApplicationError(error.message);
    }
  },

  async refreshToken(ctx) {
    const { refreshToken } = ctx.request.body || {};

    if (!refreshToken) {
      throw new ValidationError('A refresh token is required');
    }

    const user = await findUserByRefreshToken(refreshToken);

    if (!user) {
      auditCtx(ctx, { action: 'token_refresh', email: null, result: 'failed' });
      throw new ApplicationError('Invalid refresh token');
    }

    const newToken = await newRefreshToken(user.id);
    auditCtx(ctx, { action: 'token_refresh', email: user.email, result: 'success' });

    return ctx.send({
      jwt: getService('jwt').issue({ id: user.id }),
      refreshToken: newToken,
    });
  },

  async changePassword(ctx) {
    if (!ctx.state.user) {
      throw new ApplicationError('You must be authenticated to reset your password');
    }

    const { currentPassword, password } = await validateChangePasswordBody(ctx.request.body);

    const policyError = checkPasswordPolicy(password);
    if (policyError) {
      auditCtx(ctx, { action: 'user_change_password', email: ctx.state.user.email, result: 'failed' });
      throw new ValidationError(policyError);
    }

    const user = await strapi.entityService.findOne(
      'plugin::users-permissions.user',
      ctx.state.user.id
    );

    const validPassword = await getService('user').validatePassword(currentPassword, user.password);

    if (!validPassword) {
      auditCtx(ctx, { action: 'user_change_password', email: user.email, result: 'failed' });
      throw new ValidationError('The provided current password is invalid');
    }

    if (currentPassword === password) {
      auditCtx(ctx, { action: 'user_change_password', email: user.email, result: 'failed' });
      throw new ValidationError('Your new password must be different than your current password');
    }

    await getService('user').edit(user.id, { password });
    const refreshToken = await newRefreshToken(user.id);
    auditCtx(ctx, { action: 'user_change_password', email: user.email, result: 'success' });

    ctx.send({
      jwt: getService('jwt').issue({ id: user.id }),
      refreshToken,
      user: await sanitizeUser(user, ctx),
    });
  },

  async resetPassword(ctx) {
    const { password, passwordConfirmation, code } = await validateResetPasswordBody(
      ctx.request.body
    );

    if (password !== passwordConfirmation) {
      auditCtx(ctx, { action: 'user_reset_password', email: null, result: 'failed' });
      throw new ValidationError('Passwords do not match');
    }

    const policyError = checkPasswordPolicy(password);
    if (policyError) {
      auditCtx(ctx, { action: 'user_reset_password', email: null, result: 'failed' });
      throw new ValidationError(policyError);
    }

    const hashPrefix = sha256(code) + ':';
    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { resetPasswordToken: { $startsWith: hashPrefix } } });

    if (!user || !tokenValid(user.resetPasswordToken, code)) {
      auditCtx(ctx, { action: 'user_reset_password', email: null, result: 'failed' });
      throw new ValidationError('Incorrect code provided');
    }

    await getService('user').edit(user.id, {
      resetPasswordToken: null,
      password,
    });

    const refreshToken = await newRefreshToken(user.id);
    auditCtx(ctx, { action: 'user_reset_password', email: user.email, result: 'success' });

    // Update the user.
    ctx.send({
      jwt: getService('jwt').issue({ id: user.id }),
      refreshToken,
      user: await sanitizeUser(user, ctx),
    });
  },

  async connect(ctx, next) {
    const grant = require('grant-koa');

    const providers = await strapi
      .store({ type: 'plugin', name: 'users-permissions', key: 'grant' })
      .get();

    const apiPrefix = strapi.config.get('api.rest.prefix');
    const grantConfig = {
      defaults: {
        prefix: `${apiPrefix}/connect`,
      },
      ...providers,
    };

    const [requestPath] = ctx.request.url.split('?');
    const provider = requestPath.split('/connect/')[1].split('/')[0];

    if (!_.get(grantConfig[provider], 'enabled')) {
      throw new ApplicationError('This provider is disabled');
    }

    if (!strapi.config.server.url.startsWith('http')) {
      strapi.log.warn(
        'You are using a third party provider for login. Make sure to set an absolute url in config/server.js. More info here: https://docs.strapi.io/developer-docs/latest/plugins/users-permissions.html#setting-up-the-server-url'
      );
    }

    // Ability to pass OAuth callback dynamically
    grantConfig[provider].callback =
      _.get(ctx, 'query.callback') ||
      _.get(ctx, 'session.grant.dynamic.callback') ||
      grantConfig[provider].callback;
    grantConfig[provider].redirect_uri = getService('providers').buildRedirectUri(provider);

    return grant(grantConfig)(ctx, next);
  },

  async forgotPassword(ctx) {
    const { email } = await validateForgotPasswordBody(ctx.request.body);

    const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });

    const emailSettings = await pluginStore.get({ key: 'email' });
    const advancedSettings = await pluginStore.get({ key: 'advanced' });

    // Find the user by email.
    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { email: email.toLowerCase() } });

    if (!user || user.blocked) {
      auditCtx(ctx, { action: 'user_forgot_password', email: email.toLowerCase(), result: 'blocked' });
      return ctx.send({ ok: true });
    }

    // Generate random token (stored hashed with TTL in DB).
    const userInfo = await sanitizeUser(user, ctx);

    const { plain: resetPasswordToken, stored } = tokenData();

    const resetPasswordSettings = _.get(emailSettings, 'reset_password.options', {});
    const emailBody = await getService('users-permissions').template(
      resetPasswordSettings.message,
      {
        URL: advancedSettings.email_reset_password,
        SERVER_URL: getAbsoluteServerUrl(strapi.config),
        ADMIN_URL: getAbsoluteAdminUrl(strapi.config),
        USER: userInfo,
        TOKEN: resetPasswordToken,
      }
    );

    const emailObject = await getService('users-permissions').template(
      resetPasswordSettings.object,
      {
        USER: userInfo,
      }
    );

    const emailToSend = {
      to: user.email,
      from:
        resetPasswordSettings.from.email || resetPasswordSettings.from.name
          ? `${resetPasswordSettings.from.name} <${resetPasswordSettings.from.email}>`
          : undefined,
      replyTo: resetPasswordSettings.response_email,
      subject: emailObject,
      text: emailBody,
      html: emailBody,
    };

    // NOTE: Update the user before sending the email so an Admin can generate the link if the email fails
    await getService('user').edit(user.id, { resetPasswordToken: stored });
    auditCtx(ctx, { action: 'user_forgot_password', email: user.email, result: 'success' });

    // Send an email to the user.
    await strapi.plugin('email').service('email').send(emailToSend);

    ctx.send({ ok: true });
  },

  async register(ctx) {
    const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });

    const settings = await pluginStore.get({ key: 'advanced' });

    if (!settings.allow_register) {
      throw new ApplicationError('Register action is currently disabled');
    }

    const { register } = strapi.config.get('plugin.users-permissions');
    const alwaysAllowedKeys = ['username', 'password', 'email'];
    const userModel = strapi.contentTypes['plugin::users-permissions.user'];
    const { attributes } = userModel;

    const nonWritable = getNonWritableAttributes(userModel);

    const allowedKeys = compact(
      concat(
        alwaysAllowedKeys,
        isArray(register?.allowedFields)
          ? register.allowedFields
          : Object.keys(attributes).filter(
              (key) =>
                !nonWritable.includes(key) &&
                !attributes[key].private &&
                ![
                  'confirmed',
                  'blocked',
                  'confirmationToken',
                  'resetPasswordToken',
                  'provider',
                  'id',
                  'role',
                  'createdAt',
                  'updatedAt',
                  'createdBy',
                  'updatedBy',
                  'publishedAt',
                  'strapi_reviewWorkflows_stage',
                ].includes(key)
            )
      )
    );

    const params = {
      ..._.pick(ctx.request.body, allowedKeys),
      provider: 'local',
    };

    await validateRegisterBody(params);

    const policyError = checkPasswordPolicy(params.password);
    if (policyError) {
      auditCtx(ctx, { action: 'user_register', email: params.email, result: 'failed' });
      throw new ValidationError(policyError);
    }

    const role = await strapi
      .query('plugin::users-permissions.role')
      .findOne({ where: { type: settings.default_role } });

    if (!role) {
      throw new ApplicationError('Impossible to find the default role');
    }

    const { email, username, provider } = params;

    const identifierFilter = {
      $or: [
        { email: email.toLowerCase() },
        { username: email.toLowerCase() },
        { username },
        { email: username },
      ],
    };

    const conflictingUserCount = await strapi.query('plugin::users-permissions.user').count({
      where: { ...identifierFilter, provider },
    });

    if (conflictingUserCount > 0) {
      // I2: identical response shape to avoid leaking account existence
      auditCtx(ctx, { action: 'user_register', email: email.toLowerCase(), result: 'blocked' });
      return ctx.send({
        user: { username, email: email.toLowerCase(), provider },
      });
    }

    if (settings.unique_email) {
      const conflictingUserCount = await strapi.query('plugin::users-permissions.user').count({
        where: { ...identifierFilter },
      });

      if (conflictingUserCount > 0) {
        auditCtx(ctx, { action: 'user_register', email: email.toLowerCase(), result: 'blocked' });
        return ctx.send({
          user: { username, email: email.toLowerCase(), provider },
        });
      }
    }

    const newUser = {
      ...params,
      role: role.id,
      email: email.toLowerCase(),
      username,
      confirmed: !settings.email_confirmation,
    };

    const user = await getService('user').add(newUser);

    const sanitizedUser = await sanitizeUser(user, ctx);

    auditCtx(ctx, { action: 'user_register', email: user.email, result: 'success' });

    if (settings.email_confirmation) {
      try {
        await sendEmailConfirmationInternal(ctx, user);
      } catch (err) {
        throw new ApplicationError(err.message);
      }

      return ctx.send({ user: sanitizedUser });
    }

    const jwt = getService('jwt').issue(_.pick(user, ['id']));

    return ctx.send({
      jwt,
      user: sanitizedUser,
    });
  },

  async emailConfirmation(ctx, next, returnUser) {
    const { confirmation: confirmationToken } = await validateEmailConfirmationBody(ctx.query);

    const userService = getService('user');
    const jwtService = getService('jwt');

    const [user] = await userService.fetchAll({
      filters: { confirmationToken: sha256(confirmationToken) },
    });

    if (!user) {
      throw new ValidationError('Invalid token');
    }

    await userService.edit(user.id, { confirmed: true, confirmationToken: null });
    auditCtx(ctx, { action: 'user_email_confirm', email: user.email, result: 'success' });

    if (returnUser) {
      ctx.send({
        jwt: jwtService.issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    } else {
      const settings = await strapi
        .store({ type: 'plugin', name: 'users-permissions', key: 'advanced' })
        .get();

      ctx.redirect(settings.email_confirmation_redirection || '/');
    }
  },

  async sendEmailConfirmation(ctx) {
    const { email } = await validateSendEmailConfirmationBody(ctx.request.body);

    const user = await strapi.query('plugin::users-permissions.user').findOne({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      return ctx.send({ email, sent: true });
    }

    if (user.confirmed) {
      throw new ApplicationError('Already confirmed');
    }

    if (user.blocked) {
      throw new ApplicationError('User blocked');
    }

    await sendEmailConfirmationInternal(ctx, user);

    ctx.send({
      email: user.email,
      sent: true,
    });
  },
};

async function sendEmailConfirmationInternal(ctx, user) {
  const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });
  const emailSettings = await pluginStore.get({ key: 'email' });
  const advancedSettings = await pluginStore.get({ key: 'advanced' });

  const confirmationPlain = crypto.randomBytes(32).toString('hex');
  const confirmationStored = sha256(confirmationPlain);

  await getService('user').edit(user.id, { confirmationToken: confirmationStored });

  const confirmationSettings = _.get(emailSettings, 'email_confirmation.options', {});
  const body = await getService('users-permissions').template(
    (confirmationSettings && confirmationSettings.message) ||
      'Thank you for registering! Please confirm your email by clicking the link below.\n${CONFIRMATION_URL}',
    {
      URL: advancedSettings.email_confirmation_redirection,
      SERVER_URL: getAbsoluteServerUrl(strapi.config),
      ADMIN_URL: getAbsoluteAdminUrl(strapi.config),
      USER: user,
      CODE: confirmationPlain,
      TOKEN: confirmationPlain,
    }
  );

  const object = await getService('users-permissions').template(
    (confirmationSettings && confirmationSettings.object) || 'Confirm your email address',
    { USER: user }
  );

  await sendEmail({
    to: user.email,
    subject: object,
    text: body,
    html: body,
  });
}