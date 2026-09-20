'use strict';

const passport = require('koa-passport');
const compose = require('koa-compose');
const { ApplicationError, ValidationError } = require('@strapi/utils').errors;
const { getService } = require('../utils');
const {
  validateRegistrationInput,
  validateAdminRegistrationInput,
  validateRegistrationInfoQuery,
  validateForgotPasswordInput,
  validateResetPasswordInput,
  validateRenewTokenInput,
} = require('../validation/authentication');

const { otaData, otaValid, audit } = require('audit-log');

const auditCtx = (ctx, extra) =>
  audit({
    ip: (ctx.request && ctx.request.ip) || null,
    userAgent: (ctx.request && ctx.request.headers && ctx.request.headers['user-agent']) || null,
    ...extra,
  });

module.exports = {
  login: compose([
    (ctx, next) => {
      return passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err) {
          strapi.eventHub.emit('admin.auth.error', { error: err, provider: 'local' });
          // if this is a recognized error, allow it to bubble up to user
          if (err.details?.code === 'LOGIN_NOT_ALLOWED') {
            throw err;
          }

          // for all other errors throw a generic error to prevent leaking info
          return ctx.notImplemented();
        }

        if (!user) {
          strapi.eventHub.emit('admin.auth.error', {
            error: new Error(info.message),
            provider: 'local',
          });
          auditCtx(ctx, { action: 'admin_login', email: (ctx.request.body || {}).email || null, result: 'failed' });
          throw new ApplicationError(info.message);
        }

        ctx.state.user = user;

        const sanitizedUser = getService('user').sanitizeUser(user);
        strapi.eventHub.emit('admin.auth.success', { user: sanitizedUser, provider: 'local' });

        return next();
      })(ctx, next);
    },
    async (ctx) => {
      const { user } = ctx.state;

      // Au7: two-step MFA login - issue a one-time code instead of a JWT.
      const { plain: code, stored, exp } = otaData();
      const conn = strapi.db.connection('mfa_challenges');
      await conn.where({ user_id: user.id }).del();
      await conn.insert({
        user_id: user.id,
        challenge: stored,
        expires_at: exp,
      });

      const loginInfo = getService('user').sanitizeUser(ctx.state.user);
      auditCtx(ctx, { action: 'admin_mfa_challenge', email: loginInfo.email, result: 'success' });

      const emailSender = strapi.plugin('email').service('email');
      const from = strapi.config.get('admin.forgotPassword.from', undefined);
      await emailSender
        .send({
          to: loginInfo.email,
          from,
          subject: 'Admin login verification code',
          text: `Your admin login verification code is: ${code}. It expires in 5 minutes.`,
        })
        .catch((err) => strapi.log.error(err));

      ctx.body = {
        data: {
          mfaRequired: true,
          user: loginInfo,
        },
      };
    },
  ]),

  async mfaVerify(ctx) {
    const { email, code } = ctx.request.body || {};

    if (!code) {
      auditCtx(ctx, { action: 'admin_mfa_verify', email: email || null, result: 'failed' });
      throw new ValidationError('A verification code is required');
    }

    const { sha256 } = require('audit-log');

    const [row] = await strapi.db
      .connection('mfa_challenges')
      .where('challenge', 'like', sha256(String(code)) + ':%')
      .andWhere('expires_at', '>', Date.now())
      .select('*')
      .limit(1);

    if (!row || !otaValid(row.challenge, code)) {
      auditCtx(ctx, { action: 'admin_mfa_verify', email: email || null, result: 'failed' });
      throw new ValidationError('Invalid verification code');
    }

    await strapi.db.connection('mfa_challenges').where({ id: row.id }).del();

    const [user] = await strapi.db
      .connection('admin_users')
      .where({ id: row.user_id })
      .select('*')
      .limit(1);

    auditCtx(ctx, { action: 'admin_login', email: user.email, result: 'success' });

    const safeUser = getService('user').sanitizeUser(user);
    delete safeUser.password;
    delete safeUser.reset_password_token;
    delete safeUser.registration_token;

    ctx.body = {
      data: {
        token: getService('token').createJwtToken(user),
        user: safeUser,
      },
    };
  },

  async renewToken(ctx) {
    await validateRenewTokenInput(ctx.request.body);

    const { token } = ctx.request.body;

    const { isValid, payload } = getService('token').decodeJwtToken(token);

    if (!isValid) {
      throw new ValidationError('Invalid token');
    }

    ctx.body = {
      data: {
        token: getService('token').createJwtToken({ id: payload.id }),
      },
    };
  },

  async registrationInfo(ctx) {
    await validateRegistrationInfoQuery(ctx.request.query);

    const { registrationToken } = ctx.request.query;

    const registrationInfo = await getService('user').findRegistrationInfo(registrationToken);

    if (!registrationInfo) {
      throw new ValidationError('Invalid registrationToken');
    }

    ctx.body = { data: registrationInfo };
  },

  async register(ctx) {
    const input = ctx.request.body;

    await validateRegistrationInput(input);

    const user = await getService('user').register(input);

    ctx.body = {
      data: {
        token: getService('token').createJwtToken(user),
        user: getService('user').sanitizeUser(user),
      },
    };
  },

  async registerAdmin(ctx) {
    const input = ctx.request.body;

    await validateAdminRegistrationInput(input);

    const hasAdmin = await getService('user').exists();

    if (hasAdmin) {
      throw new ApplicationError('You cannot register a new super admin');
    }

    const superAdminRole = await getService('role').getSuperAdmin();

    if (!superAdminRole) {
      throw new ApplicationError(
        "Cannot register the first admin because the super admin role doesn't exist."
      );
    }

    const user = await getService('user').create({
      ...input,
      registrationToken: null,
      isActive: true,
      roles: superAdminRole ? [superAdminRole.id] : [],
    });

    strapi.telemetry.send('didCreateFirstAdmin');

    ctx.body = {
      data: {
        token: getService('token').createJwtToken(user),
        user: getService('user').sanitizeUser(user),
      },
    };
  },

  async forgotPassword(ctx) {
    const input = ctx.request.body;

    await validateForgotPasswordInput(input);

    getService('auth').forgotPassword(input);

    auditCtx(ctx, { action: 'admin_forgot_password', email: (input || {}).email || null, result: 'success' });

    ctx.status = 204;
  },

  async resetPassword(ctx) {
    const input = ctx.request.body;

    await validateResetPasswordInput(input);

    const user = await getService('auth').resetPassword(input);

    auditCtx(ctx, { action: 'admin_reset_password', email: user && user.email, result: 'success' });

    ctx.body = {
      data: {
        token: getService('token').createJwtToken(user),
        user: getService('user').sanitizeUser(user),
      },
    };
  },

  logout(ctx) {
    const sanitizedUser = getService('user').sanitizeUser(ctx.state.user);
    auditCtx(ctx, { action: 'admin_logout', email: sanitizedUser.email, result: 'success' });
    strapi.eventHub.emit('admin.logout', { user: sanitizedUser });
    ctx.body = { data: {} };
  },
};