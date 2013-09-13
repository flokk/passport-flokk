/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Flokk authentication strategy authenticates requests by delegating to
 * Flokk using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Flokk application's App ID
 *   - `clientSecret`  your Flokk application's App Secret
 *   - `callbackURL`   URL to which Flokk will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.
 * Examples:
 *
 *     passport.use(new FlokkStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/flokk/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function FlokkStrategy(options, verify) {
  options = options || {};
  options.host = options.host || "https://auth.theflokk.com";
  options.authorizationURL = options.authorizationURL || "/authorize";
  options.tokenURL = options.tokenURL || "/token";

  OAuth2Strategy.call(this, options, verify);

  this._host = options.host;
  this.name = 'flokk';
}

/**
 * Inherit from `OAuth2Strategy`.
 */

util.inherits(FlokkStrategy, OAuth2Strategy);

/**
 * We need to override this so we can dynamically set the auth server host
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */

FlokkStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  // Luckily there's no race condition that exists in the current
  // implementation of the oauth lib with setting the `_baseSite`
  // for each request - make sure one does not happen in the future
  this._oauth2._baseSite = options.host || this._host;
  OAuth2Strategy.prototype.authenticate.apply(this, arguments);
}

/**
 * We need to allow the extra parameters go through
 *
 *   The following options are supported
 *
 *     register: prompt the user to register instead of login
 *
 * @param {Object} options
 * @return {Object}
 */

FlokkStrategy.prototype.authorizationParams = function(options) {
  var extra = {};

  if (options.register) extra.register = options.register;

  return extra;
}

/**
 * Retrieve user profile from Flokk.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `flokk`
 *   - `id`               the user's Flokk ID
 *   - `username`         the user's Flokk username
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on Flokk
 *   - `emails`           the user's email addresses
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

FlokkStrategy.prototype.userProfile = function(accessToken, done) {
  // TODO make this url configurable
  this._oauth2.get('https://api.theflokk.com/account', accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);

      var profile = { provider: 'flokk' };
      profile.id = json.id;
      profile.displayName = json.name;
      profile.username = json.username;
      profile.profileUrl = json.href;
      profile.emails = [];

      if (json.email) {
        if (!json.email instanceof Array) json.email = [json.email];

        json.email.forEach(function(email) {
          profile.emails.push({ value: email.href || email });
        });
      }

      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `FlokkStrategy`.
 */

module.exports = FlokkStrategy;
