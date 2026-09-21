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

const { otaData, otaValid, audit, checkPasswordPolicy, createAttemptTracker, ensureTable } =
  require('audit-log');

const auditCtx = (ctx, extra) => {
  const stateUser = ctx.state && ctx.state.user;
  const username = (stateUser && (stateUser.username || stateUser.email)) || null;
  return audit({
    ip: (ctx.request && ctx.request.ip) || null,
    userAgent: (ctx.request && ctx.request.headers && ctx.request.headers['user-agent']) || null,
    username,
    ...extra,
  });
};

// Au8/Au9: account-level lockout after 5 failed password tries in 15 min (auto-unlocks).
const PASSWORD_MAX_ATTEMPTS = 5;
const PASSWORD_LOCKOUT_WINDOW_MS = 15 * 60 * 1000;
const passwordFailures = createAttemptTracker({
  max: PASSWORD_MAX_ATTEMPTS,
  windowMs: PASSWORD_LOCKOUT_WINDOW_MS,
});

// Au8: MFA code lockout, keyed by email (not shared proxy IP) to avoid mutual DoS.
const MFA_MAX_ATTEMPTS = 5;
const MFA_LOCKOUT_WINDOW_MS = 15 * 60 * 1000;
const mfaFailures = createAttemptTracker({
  max: MFA_MAX_ATTEMPTS,
  windowMs: MFA_LOCKOUT_WINDOW_MS,
});

const loginKey = (email) => String(email || '').toLowerCase();

module.exports = {
  login: compose([
    async (ctx, next) => {
      const email = ((ctx.request.body || {}).email || '').toString().trim();
      const emailKey = loginKey(email);

      if (emailKey && (await passwordFailures.isLocked(emailKey))) {
        auditCtx(ctx, {
          action: 'admin_login',
          email: email || null,
          username: email || null,
          result: 'locked',
        });
        throw new ApplicationError('Too many failed attempts. Try again later.');
      }

      return passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err) {
          strapi.eventHub.emit('admin.auth.error', { error: err, provider: 'local' });
          if (err.details?.code === 'LOGIN_NOT_ALLOWED') {
            // I2: never disclose blocked status; answer like any other failed login.
            auditCtx(ctx, {
              action: 'admin_login',
              email: email || null,
              username: email || null,
              result: 'failed',
            });
            throw new ApplicationError('Invalid credentials');
          }

          // for all other errors throw a generic error to prevent leaking info
          return ctx.notImplemented();
        }

        if (!user) {
          strapi.eventHub.emit('admin.auth.error', {
            error: new Error(info.message),
            provider: 'local',
          });
          if (emailKey) void passwordFailures.markFailure(emailKey);
          auditCtx(ctx, {
            action: 'admin_login',
            email: email || null,
            username: email || null,
            result: 'failed',
          });
          throw new ApplicationError(info.message);
        }

        if (emailKey) void passwordFailures.clear(emailKey);

        ctx.state.user = user;

        const sanitizedUser = getService('user').sanitizeUser(user);
        strapi.eventHub.emit('admin.auth.success', { user: sanitizedUser, provider: 'local' });

        return next();
      })(ctx, next);
    },
    async (ctx) => {
      const { user } = ctx.state;

      await ensureTable('mfa_challenges', (table) => {
        table.increments('id');
        table.integer('user_id');
        table.string('challenge', 128);
        table.bigInteger('expires_at');
      });

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
      auditCtx(ctx, {
        action: 'admin_mfa_challenge',
        email: loginInfo.email,
        username: loginInfo.username || loginInfo.email,
        result: 'success',
      });

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
    const key = loginKey(email || '');

    if (!code) {
      auditCtx(ctx, {
        action: 'admin_mfa_verify',
        email: email || null,
        username: loginKey(email || null),
        result: 'failed',
      });
      throw new ValidationError('A verification code is required');
    }

    if (key && (await mfaFailures.isLocked(key))) {
      auditCtx(ctx, {
        action: 'admin_mfa_verify',
        email: email || null,
        username: loginKey(email || null),
        result: 'locked',
      });
      throw new ValidationError('Too many failed attempts. Try again later.');
    }

    const { sha256 } = require('audit-log');

    const [row] = await strapi.db
      .connection('mfa_challenges')
      .where('challenge', 'like', sha256(String(code)) + ':%')
      .andWhere('expires_at', '>', Date.now())
      .select('*')
      .limit(1);

    if (!row || !otaValid(row.challenge, code)) {
      if (key) await mfaFailures.markFailure(key);
      auditCtx(ctx, {
        action: 'admin_mfa_verify',
        email: email || null,
        username: loginKey(email || null),
        result: 'failed',
      });
      throw new ValidationError('Invalid verification code');
    }

    if (key) await mfaFailures.clear(key);

    const user = await strapi.query('admin::user').findOne({ where: { id: row.user_id } });

    if (!user || user.isActive !== true) {
      auditCtx(ctx, {
        action: 'admin_login',
        email: (user && user.email) || email || null,
        result: 'failed',
        username: (user && user.username) || email || null,
      });
      throw new ValidationError('Invalid verification code');
    }

    await strapi.db.connection('mfa_challenges').where({ id: row.id }).del();

    auditCtx(ctx, { action: 'admin_login', email: user.email, result: 'success', username: user.username || user.email });

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
      auditCtx(ctx, { action: 'admin_renew_token', email: null, result: 'failed' });
      throw new ValidationError('Invalid token');
    }

    const adminUser = await strapi
      .query('admin::user')
      .findOne({ where: { id: payload.id } });

    if (!adminUser || adminUser.isActive !== true) {
      auditCtx(ctx, { action: 'admin_renew_token', email: null, result: 'failed' });
      throw new ValidationError('Invalid token');
    }

    auditCtx(ctx, {
      action: 'admin_renew_token',
      email: adminUser.email,
      username: adminUser.username || adminUser.email,
      result: 'success',
    });

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

    const policyError = checkPasswordPolicy(
      input && input.userInfo && input.userInfo.password
    );
    if (policyError) {
      auditCtx(ctx, {
        action: 'admin_register',
        email: (input && input.userInfo && input.userInfo.email) || null,
        username:
          (input &&
            input.userInfo &&
            (input.userInfo.username || input.userInfo.email)) ||
          null,
        result: 'failed',
      });
      throw new ValidationError(policyError);
    }

    const user = await getService('user').register(input);

    auditCtx(ctx, {
      action: 'admin_register',
      email: (user && user.email) || (input && input.email) || null,
      username: (user && (user.username || user.email)) || null,
      result: 'success',
    });

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

    const policyError = checkPasswordPolicy(input.password);
    if (policyError) {
      throw new ValidationError(policyError);
    }

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

    auditCtx(ctx, {
      action: 'admin_register_admin',
      email: user.email,
      username: user.username || user.email,
      result: 'success',
    });

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

    await getService('auth').forgotPassword(input);

    const email = (input && input.email) ? String(input.email).toLowerCase() : null;
    auditCtx(ctx, {
      action: 'admin_forgot_password',
      email,
      username: email,
      result: 'success',
    });

    ctx.status = 204;
  },

  async resetPassword(ctx) {
    const input = ctx.request.body;

    await validateResetPasswordInput(input);

    const user = await getService('auth').resetPassword(input);

    auditCtx(ctx, {
      action: 'admin_reset_password',
      email: user && user.email,
      result: 'success',
      username: (user && (user.username || user.email)) || null,
    });

    ctx.body = {
      data: {
        token: getService('token').createJwtToken(user),
        user: getService('user').sanitizeUser(user),
      },
    };
  },

  logout(ctx) {
    const sanitizedUser = getService('user').sanitizeUser(ctx.state.user);
    auditCtx(ctx, {
      action: 'admin_logout',
      email: sanitizedUser.email,
      result: 'success',
      username: sanitizedUser.username || sanitizedUser.email,
    });
    strapi.eventHub.emit('admin.logout', { user: sanitizedUser });
    ctx.body = { data: {} };
  },
};