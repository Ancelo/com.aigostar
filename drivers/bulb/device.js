'use strict';

const Homey = require('homey');
const aigostar = require('../../lib/aigostar-api');

const POLL_INTERVAL_MS = 15 * 1000; // how often we pull state from the cloud (no push available)
const CONFIRM_POLL_MS = 2000; // quick re-poll after a command, to confirm the new state fast
const POLL_SUPPRESS_MS = 6000; // ignore periodic-poll writes briefly after a command (avoid slider fights)

class AigostarBulbDevice extends Homey.Device {
  async onInit() {
    this.log('Aigostar bulb device initialized:', this.getName());

    const store = this.getStore();
    this._iotToken = store.iotToken;
    this._refreshToken = store.refreshToken;
    this._identityId = store.identityId;
    // Reconstruct the real expiry deadline from the values saved at pairing /
    // last refresh. Devices paired before these fields existed have neither,
    // so we treat the token as already expired and refresh on the first poll.
    if (store.tokenCreatedAt && store.iotTokenExpire) {
      this._tokenExpiresAt = store.tokenCreatedAt + Number(store.iotTokenExpire) * 1000;
    } else {
      this._tokenExpiresAt = 0;
    }

    const iotId = this.getData().id;
    this._client = new aigostar.AlibabaIoTDevice(iotId, this._iotToken);

    // Migration: bulbs paired before colour support gained only onoff/dim/
    // light_temperature. Add the colour capabilities to existing devices so
    // the listeners below (and the UI colour wheel) work for them too.
    for (const cap of ['light_hue', 'light_saturation', 'light_mode']) {
      if (!this.hasCapability(cap)) {
        await this.addCapability(cap).catch((err) => this.error(`addCapability ${cap}:`, err.message));
      }
    }

    this.registerCapabilityListener('onoff', this._onCapabilityOnoff.bind(this));
    // dim / colour / temperature / mode are batched: when the user picks a
    // colour, Homey delivers hue + saturation (and often dim) together, so we
    // send a single coherent HSV/white command instead of three racing ones.
    this.registerMultipleCapabilityListener(
      ['dim', 'light_hue', 'light_saturation', 'light_temperature', 'light_mode'],
      this._onCapabilitiesSet.bind(this),
      300
    );

    this._ignorePollUntil = 0;
    await this._safePoll();
    this._pollTimer = this.homey.setInterval(() => this._safePoll(false), POLL_INTERVAL_MS);
  }

  // Quick one-shot poll shortly after a command so Homey reflects the real
  // device state fast. Also suppress the periodic poll for a short window so a
  // background poll can't overwrite a slider the user is actively dragging.
  _scheduleConfirmPoll() {
    this._ignorePollUntil = Date.now() + POLL_SUPPRESS_MS;
    if (this._confirmTimer) this.homey.clearTimeout(this._confirmTimer);
    this._confirmTimer = this.homey.setTimeout(() => this._safePoll(true), CONFIRM_POLL_MS);
  }

  async onDeleted() {
    if (this._confirmTimer) this.homey.clearTimeout(this._confirmTimer);
    if (this._pollTimer) this.homey.clearInterval(this._pollTimer);
  }

  // -------------------------------------------------------------------
  // Token management
  // -------------------------------------------------------------------

  // Persist a fresh session (from refreshIotToken or a full re-login) and
  // point the live client at the new token.
  async _applySession(data) {
    this._iotToken = data.iotToken;
    this._refreshToken = data.refreshToken || this._refreshToken;
    if (data.identityId) this._identityId = data.identityId;
    this._client.iotToken = this._iotToken;

    const expireSec = Number(data.iotTokenExpire) || 72000;
    this._tokenExpiresAt = Date.now() + expireSec * 1000;

    await this.setStoreValue('iotToken', this._iotToken);
    await this.setStoreValue('refreshToken', this._refreshToken);
    await this.setStoreValue('identityId', this._identityId);
    await this.setStoreValue('iotTokenExpire', expireSec);
    await this.setStoreValue('tokenCreatedAt', Date.now());
  }

  // Adopt a token another bulb may have just refreshed, cheaply and without
  // any network call. This is what stops the login war: once one bulb renews
  // the shared session, the rest pick it up instead of logging in themselves.
  async _adoptSharedSession() {
    const shared = this.driver.getSharedSession();
    if (shared && shared.iotToken && shared.iotToken !== this._iotToken) {
      await this._applySession(shared);
      return true;
    }
    return false;
  }

  // Renew via the driver's shared session (compare-and-swap): only the first
  // bulb still on the stale token triggers an actual login; the rest adopt it.
  // The lightweight refreshToken path is dead on this account, so we don't
  // even attempt it here.
  async _renewSession() {
    const session = await this.driver.renewSharedSession(this._iotToken);
    await this._applySession(session);
  }

  async _ensureFreshToken() {
    // Cheaply adopt a token another bulb already refreshed before checking
    // our own expiry, so we never trigger a redundant login.
    await this._adoptSharedSession();
    // Renew proactively 30 min before expiry so a live command never races an
    // expiring token.
    if (Date.now() < this._tokenExpiresAt - 30 * 60 * 1000) return;
    await this._renewSession();
  }

  // -------------------------------------------------------------------
  // Polling
  // -------------------------------------------------------------------

  async _pollOnce(apply = true) {
    const props = await this._client.getProperties();

    // Logged at info level so RGB-specific fields (not present in the
    // reference white-only model) can be identified for this bulb during
    // initial bring-up of color support.
    this.log('Raw TSL properties:', JSON.stringify(props));

    // Reaching here means the device is reachable; the caller handles
    // availability. When `apply` is false we skip writing capability values
    // (a background poll shortly after a command must not fight the user).
    if (!apply) return;

    if (aigostar.PROP_SWITCH in props) {
      const isOn = !!props[aigostar.PROP_SWITCH];
      if (this.getCapabilityValue('onoff') !== isOn) {
        await this.setCapabilityValue('onoff', isOn).catch(this.error);
      }
    }

    const isColor = Number(props[aigostar.PROP_LIGHT_MODE]) === 1;
    if (aigostar.PROP_LIGHT_MODE in props && this.hasCapability('light_mode')) {
      await this.setCapabilityValue('light_mode', isColor ? 'color' : 'temperature').catch(this.error);
    }

    const hsv = props[aigostar.PROP_HSV];
    if (isColor && hsv && typeof hsv === 'object') {
      // In colour mode the perceived brightness lives in HSVColor.Value.
      if ('Value' in hsv) {
        await this.setCapabilityValue('dim', aigostar.aigoBrightnessToHomeyDim(Number(hsv.Value))).catch(this.error);
      }
      if ('Hue' in hsv && this.hasCapability('light_hue')) {
        await this.setCapabilityValue('light_hue', aigostar.aigoHueToHomey(hsv.Hue)).catch(this.error);
      }
      if ('Saturation' in hsv && this.hasCapability('light_saturation')) {
        await this.setCapabilityValue('light_saturation', aigostar.aigoSatToHomey(hsv.Saturation)).catch(this.error);
      }
    } else if (aigostar.PROP_BRIGHTNESS in props) {
      // White mode: the dedicated brightness field drives dim.
      await this.setCapabilityValue('dim', aigostar.aigoBrightnessToHomeyDim(Number(props[aigostar.PROP_BRIGHTNESS]))).catch(this.error);
    }

    if (aigostar.PROP_COLOR_TEMP in props) {
      const temp = aigostar.aigoTempToHomey(Number(props[aigostar.PROP_COLOR_TEMP]));
      await this.setCapabilityValue('light_temperature', temp).catch(this.error);
    }
  }

  async _safePoll(isConfirm = false) {
    // A confirm poll always applies; a periodic poll skips writing capability
    // values while we're in the post-command suppression window.
    const apply = isConfirm || Date.now() >= (this._ignorePollUntil || 0);
    try {
      await this._ensureFreshToken();
      await this._pollOnce(apply);
      if (!this.getAvailable()) await this.setAvailable().catch(this.error);
      return;
    } catch (err) {
      // The poll can still fail with a locally-fresh token if the session was
      // invalidated server-side mid-cycle (e.g. the phone app logged in).
      this.log('Poll failed, attempting session recovery:', err.message);
    }

    try {
      await this._renewSession();
      await this._pollOnce(apply);
      if (!this.getAvailable()) await this.setAvailable().catch(this.error);
      this.log('Recovered device availability for', this.getName());
    } catch (err2) {
      this.error('Device unavailable, recovery failed:', err2.message);
      await this.setUnavailable(err2.message).catch(() => {});
    }
  }

  // -------------------------------------------------------------------
  // Capability listeners
  // -------------------------------------------------------------------

  // Send a command with the same self-heal the poll path uses: if the shared
  // session was rotated by another bulb mid-flight (common when a group action
  // commands several bulbs at once), the first attempt gets a 401; renew and
  // retry once so the command isn't silently dropped for that one bulb.
  async _sendProperties(items) {
    await this._ensureFreshToken();
    try {
      await this._client.setProperties(items);
    } catch (err) {
      this.log('Command failed, retrying after session renew:', err.message);
      await this._renewSession();
      await this._client.setProperties(items);
    }
  }

  async _onCapabilityOnoff(value) {
    await this._sendProperties({ [aigostar.PROP_SWITCH]: value ? 1 : 0 });
    this._scheduleConfirmPoll();
  }

  // Handles dim, colour (hue/saturation), colour-temperature and mode changes.
  // `values` holds only the capabilities that actually changed, so we send the
  // minimum coherent command: e.g. a dim-only change must NOT re-send colour
  // temperature (that used to snap the bulb's temperature to 50%).
  async _onCapabilitiesSet(values) {
    const cur = (cap) => (this.hasCapability(cap) ? this.getCapabilityValue(cap) : null);
    const has = (cap) => cap in values;

    const wantColour = has('light_hue') || has('light_saturation') || values.light_mode === 'color';
    const wantTemp = has('light_temperature') || values.light_mode === 'temperature';

    const items = {};

    if (wantColour) {
      // Colour command: full HSV (hue/sat from values or current; brightness
      // from dim if it changed, else keep current).
      items[aigostar.PROP_LIGHT_MODE] = 1;
      items[aigostar.PROP_HSV] = {
        Hue: aigostar.homeyHueToAigo(has('light_hue') ? values.light_hue : (cur('light_hue') ?? 0)),
        Saturation: aigostar.homeySatToAigo(has('light_saturation') ? values.light_saturation : (cur('light_saturation') ?? 1)),
        Value: aigostar.homeyDimToAigoBrightness(has('dim') ? values.dim : (cur('dim') ?? 1)),
      };
    } else if (wantTemp) {
      // White/temperature command.
      items[aigostar.PROP_LIGHT_MODE] = 0;
      items[aigostar.PROP_COLOR_TEMP] = aigostar.homeyTempToAigo(
        has('light_temperature') ? values.light_temperature : (cur('light_temperature') ?? 0.5)
      );
      if (has('dim')) items[aigostar.PROP_BRIGHTNESS] = aigostar.homeyDimToAigoBrightness(values.dim);
    } else if (has('dim')) {
      // Pure brightness change: adjust in whatever mode the bulb is already in,
      // without touching colour or temperature.
      if (cur('light_mode') === 'color') {
        items[aigostar.PROP_LIGHT_MODE] = 1;
        items[aigostar.PROP_HSV] = {
          Hue: aigostar.homeyHueToAigo(cur('light_hue') ?? 0),
          Saturation: aigostar.homeySatToAigo(cur('light_saturation') ?? 1),
          Value: aigostar.homeyDimToAigoBrightness(values.dim),
        };
      } else {
        items[aigostar.PROP_BRIGHTNESS] = aigostar.homeyDimToAigoBrightness(values.dim);
      }
    }

    if (has('dim') && values.dim > 0) {
      items[aigostar.PROP_SWITCH] = 1;
      // Optimistic: raising brightness implies the bulb turns on, so reflect
      // that in the UI immediately rather than waiting for the confirm poll.
      if (this.getCapabilityValue('onoff') !== true) {
        await this.setCapabilityValue('onoff', true).catch(this.error);
      }
    }

    if (Object.keys(items).length === 0) return;
    await this._sendProperties(items);
    this._scheduleConfirmPoll();
  }

  // Used by the 'set_color_temperature_percent' flow action: sets the raw
  // Aigostar 0-100 scale directly (0=warm, 100=cool) without going through
  // the Homey light_temperature capability's inverted 0-1 scale.
  async triggerSetColorTemperaturePercent(percent) {
    const clamped = Math.max(0, Math.min(100, Math.round(percent)));
    await this._sendProperties({
      [aigostar.PROP_COLOR_TEMP]: clamped,
      [aigostar.PROP_LIGHT_MODE]: 0,
    });
    const homeyTemp = aigostar.aigoTempToHomey(clamped);
    await this.setCapabilityValue('light_temperature', homeyTemp).catch(this.error);
    this._scheduleConfirmPoll();
  }
}

module.exports = AigostarBulbDevice;
