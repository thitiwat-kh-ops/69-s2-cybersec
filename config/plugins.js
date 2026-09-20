module.exports = ({ env }) => ({
  email: {
    config: {
      provider: 'console',
    },
  },
  'users-permissions': {
    config: {
      jwt: {
        expiresIn: '15m',
      },
    },
  },
});