'use strict';

const Homey = require('homey');
const crypto = require('crypto');
const aigostar = require('../../lib/aigostar-api');

class AigostarBulbDriver extends Homey.Driver {
  async onInit() {
    this.log('Aigostar bulb driver initialized');
  }

  async _getOrCreateDeviceId() {
    const STORE_KEY = 'aigostar_device_id';
    let id = this.homey.settings.get(STORE_KEY);
    if (!id) {
      id = crypto.randomBytes(16).toString('hex'); // 32 hex chars, like the reference uuid5
      this.homey.settings.set(STORE_KEY, id);
      this.log('Generated new persistent device id for Aigostar login');
    }
    return id;
  }

  // -------------------------------------------------------------------
  // Shared session (single source of truth for all bulbs)
  //
  // The Alibaba backend allows only ONE active session per account/cuid:
  // every fullLogin() invalidates the iotToken issued by the previous one.
  // With 14 bulbs each holding and refreshing their own token on staggered
  // 30s timers, they were invalidating each other in an endless login war
  // (bulb A logs in -> kills everyone else's token -> they all re-login ->
  // kills A's token -> ...). The lightweight refreshToken path is also dead
  // on this account (always "refreshToken invalid"), so a full login is the
  // only way to renew.
  //
  // The fix: the driver owns a single shared session. Bulbs never log in on
  // their own; they call renewSharedSession(staleToken). If another bulb has
  // already refreshed since `staleToken` was issued, they just adopt the new
  // token (compare-and-swap) instead of triggering another login. Net result:
  // exactly one login per real invalidation, not one per bulb.
  // -------------------------------------------------------------------

  getSharedSession() {
    return this._session || null;
  }

  // Return a session whose iotToken differs from `staleToken`. If the shared
  // session already moved past it, hand that back without logging in; only the
  // first caller (still on the stale token) triggers an actual login.
  async renewSharedSession(staleToken) {
    if (this._session && this._session.iotToken && this._session.iotToken !== staleToken) {
      return this._session;
    }
    return this.reLogin();
  }

  async reLogin() {
    const email = this.homey.settings.get('aigosmart_email');
    const password = this.homey.settings.get('aigosmart_password');
    if (!email || !password) {
      // Missing credentials is a configuration state, not a rate-limit one, so
      // we do NOT arm the cooldown: the moment a device is (re-)paired and the
      // credentials get saved, recovery happens on the very next poll.
      throw new Error('No stored Aigostar credentials; please add or re-pair a device once.');
    }

    // Coalesce concurrent attempts from all bulbs into a single login.
    if (this._reLoginPromise) return this._reLoginPromise;
    if (this._reLoginBlockedUntil && Date.now() < this._reLoginBlockedUntil) {
      throw new Error('Re-login backing off after a recent failure');
    }

    this._reLoginPromise = (async () => {
      const deviceId = await this._getOrCreateDeviceId();
      const session = await aigostar.fullLogin(email, password, deviceId, '');
      this._session = session; // { iotToken, refreshToken, identityId, iotTokenExpire }
      this.log('Re-login successful, fresh iotToken obtained');
      return session;
    })();

    try {
      const session = await this._reLoginPromise;
      this._reLoginBlockedUntil = 0;
      return session;
    } catch (err) {
      // Back off for 5 minutes so a persistent failure (wrong password, rate
      // limiting) doesn't turn into a tight login loop across all bulbs.
      this._reLoginBlockedUntil = Date.now() + 5 * 60 * 1000;
      throw err;
    } finally {
      this._reLoginPromise = null;
    }
  }

  _saveCredentials(email, password) {
    // Persisted app-wide so reLogin() can run unattended for every bulb.
    this.homey.settings.set('aigosmart_email', email);
    this.homey.settings.set('aigosmart_password', password);
  }

  async onPair(session) {
    this.log('onPair() called - pairing session started');
    let email = '';
    let password = '';
    let sessionData = null; // { iotToken, refreshToken, identityId, iotTokenExpire }
    let discoveredDevices = [];

    // Persistent, randomly-generated device id, stored once and reused on
    // every pairing attempt. Aigostar's backend appears to rate-limit /
    // deduplicate verification-code requests per device id, so a stable
    // value here is required for the "resend code" flow to behave sanely.
    const deviceId = await this._getOrCreateDeviceId();

    session.setHandler('login', async (data) => {
      email = (data.username || '').trim();
      password = data.password || '';

      try {
        sessionData = await aigostar.fullLogin(email, password, deviceId, '');
        this._saveCredentials(email, password);
        return true;
      } catch (err) {
        if (err instanceof aigostar.NeedSecurityCodeError) {
          this.log('Aigostar requires a verification code, requesting one for', email);
          try {
            await aigostar.sendVerificationCode(email);
          } catch (sendErr) {
            this.error('Failed to send verification code:', sendErr.message);
            // Surface this to the user rather than silently showing an
            // empty "enter code" screen with no code ever sent.
            throw new Error(
              `Could not send verification code: ${sendErr.message}`
            );
          }
          return { needsCode: true };
        }
        this.error('Login failed:', err.message);
        throw new Error(err.message || 'Login failed');
      }
    });

    session.setHandler('verify_code', async (data) => {
      const code = data.code || '';
      try {
        sessionData = await aigostar.fullLogin(email, password, deviceId, code);
        this._saveCredentials(email, password);
        return true;
      } catch (err) {
        this.error('Verification failed:', err.message);
        throw new Error(err.message || 'Verification failed');
      }
    });

    session.setHandler('list_devices', async () => {
      if (!sessionData || !sessionData.iotToken) {
        throw new Error('Not logged in');
      }
      // Seed the shared session so freshly-paired bulbs adopt this token
      // instead of each triggering their own (mutually-invalidating) login.
      this._session = sessionData;

      const raw = await aigostar.listDevices(sessionData.iotToken);
      discoveredDevices = raw;

      return raw.map((dev) => {
        const iotId = dev.iotId || dev.deviceId || '';
        const name = dev.nickName || dev.deviceName || `Aigostar bulb (${iotId.slice(0, 6)})`;
        return {
          name,
          data: { id: iotId },
          store: {
            iotToken: sessionData.iotToken,
            refreshToken: sessionData.refreshToken,
            identityId: sessionData.identityId,
            iotTokenExpire: Number(sessionData.iotTokenExpire) || 72000,
            tokenCreatedAt: Date.now(),
            email,
          },
        };
      });
    });
  }
}

module.exports = AigostarBulbDriver;
