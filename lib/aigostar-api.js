'use strict';

/**
 * Aigostar / Alibaba Cloud IoT API client (eu-central-1).
 *
 * Node.js port of the protocol reverse-engineered from the AigoSmart
 * Android APK, documented in:
 *   https://github.com/MarcoM1993/ha-aigostar
 *
 * Login flow (5 steps):
 *   1. POST uc.aigostar.com/v1.0/connect/token        -> access_token
 *   2. GET  uc.aigostar.com/v1.0/connect/authorize     -> authCode
 *   3. POST api.link.aliyun.com/living/account/region/get -> oaApiGatewayEndpoint
 *   4. POST {oaHost}/api/prd/loginbyoauth.json         -> sid (OA session)
 *   5. POST api-iot/account/createSessionByAuthCode    -> iotToken + refreshToken
 *
 * This is an unofficial, community-built client. It is not affiliated
 * with or endorsed by Aigostar / Alibaba.
 */

const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');

// --- Alibaba Cloud IoT Gateway ---
const BASE_URL = 'https://eu-central-1.api-iot.aliyuncs.com';
const PATH_GET = '/thing/properties/get';
const PATH_SET = '/thing/properties/set';
const PATH_DEVICES = '/uc/listBindingByAccount';
const PATH_CREATE_SESSION = '/account/createSessionByAuthCode';
const PATH_REFRESH = '/account/checkOrRefreshSession';
const CONTENT_TYPE = 'application/json; charset=UTF-8';
const ACCEPT = 'application/json; charset=UTF-8';

// --- Region discovery & OAuth login ---
const REGION_API_HOST = 'https://api.link.aliyun.com';
const REGION_API_PATH = '/living/account/region/get';
const OA_LOGIN_PATH = '/api/prd/loginbyoauth.json';
const OA_HOST_FALLBACK = 'living-account.eu-central-1.aliyuncs.com';

// --- Aigostar User Center ---
const UC_BASE = 'https://uc.aigostar.com';
const UC_LOGIN = '/v1.0/connect/token';
const UC_AUTHORIZE = '/v1.0/connect/authorize';

// OAuth client credentials (public values extracted from the APK, not user secrets)
const CLIENT_ID = 'C28098DEE9664BABBB9AE8E6E47505B0';
const CLIENT_SECRET = 'C3575D1E-7A5F-411F-920D-5C469AA53AB7';
const SMARTAPP_ID = 'smartapp';

// AES key for password encryption (matches the Android app)
const AES_KEY = 'tCx8BA0yKVr+NbBChH928URAV90=0000';

// Headers required by the Android app's OkHttp interceptor
const UC_APP_KEY = 'smart-android-v1';
const UC_TENANT_ID = '1000';

// Public app credentials for the IoT gateway (extracted from the APK)
const APP_KEY = '28770785';
const APP_SECRET = '41fd4a1eb18fa7ace5e2abbbe3867f93';

// TSL properties for the Aigostar RGB bulb model (discovered empirically from
// the live devices; note these differ from the white-only TG7100C names such
// as LightSwitch/Brightness/ColorTemperature):
//   powerstate       0/1
//   brightness       1-100
//   colorTemperature 0-100  (0=warm, 100=cool)
//   LightMode        0=white, 1=color
//   HSVColor         { Hue:0-360, Saturation:0-100, Value:0-100 }
const PROP_SWITCH = 'powerstate';
const PROP_BRIGHTNESS = 'brightness';
const PROP_COLOR_TEMP = 'colorTemperature';
const PROP_LIGHT_MODE = 'LightMode';
const PROP_HSV = 'HSVColor';

const KELVIN_WARM = 2700;
const KELVIN_COOL = 6500;

// ===========================================================================
// Low-level HTTP helper
// ===========================================================================

function httpRequest(method, urlStr, headers, bodyBuffer) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const options = {
      method,
      hostname: u.hostname,
      path: u.pathname + u.search,
      port: 443,
      headers: Object.assign({}, headers),
    };
    if (bodyBuffer) {
      options.headers['Content-Length'] = Buffer.byteLength(bodyBuffer);
    }
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve({ statusCode: res.statusCode, body: raw });
      });
    });
    req.on('error', reject);
    if (bodyBuffer) req.write(bodyBuffer);
    req.end();
  });
}

function safeJsonParse(raw) {
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

// ===========================================================================
// UC signature (MD5-based, from the AigoSmart RetrofitServiceManager interceptor)
// ===========================================================================

function ucMd5(text) {
  return crypto.createHash('md5').update(text, 'utf8').digest('hex').toUpperCase();
}

function ucSignRequest(method, url, timestamp) {
  let sortedParams = '';
  let baseUrl = url;
  if (url.includes('?')) {
    const [base, qs] = url.split('?');
    baseUrl = base;
    const pairs = {};
    qs.split('&').forEach((part) => {
      const idx = part.indexOf('=');
      if (idx > -1) {
        pairs[part.slice(0, idx)] = part.slice(idx + 1);
      }
    });
    const sortedKeys = Object.keys(pairs).sort();
    sortedParams = sortedKeys.map((k) => `${k}${pairs[k]}`).join(',');
  }
  let signKey = UC_APP_KEY + AES_KEY + timestamp + method.toUpperCase() + baseUrl;
  if (sortedParams) signKey += sortedParams;
  return ucMd5(signKey);
}

function ucHeaders(method, url) {
  const ts = String(Date.now());
  return {
    AppKey: UC_APP_KEY,
    Timestamp: ts,
    TenantId: UC_TENANT_ID,
    Signature: ucSignRequest(method, url, ts),
  };
}

// ===========================================================================
// AES-256-CBC password encryption (zero IV, matches AigoSmart app)
// ===========================================================================

function encryptPassword(password) {
  const key = Buffer.from(AES_KEY, 'utf8'); // 32 bytes -> AES-256
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
  return encrypted.toString('base64');
}

// ===========================================================================
// x-ca-signature helpers (shared by IoT Gateway API calls)
// ===========================================================================

function contentMd5(bodyBuffer) {
  return crypto.createHash('md5').update(bodyBuffer).digest('base64');
}

function buildCanonical(method, path, contentMd5Value, date, signHeaders) {
  const sortedKeys = Object.keys(signHeaders).sort();
  const canonicalHdrs = sortedKeys.map((k) => `${k}:${signHeaders[k]}`).join('\n');
  return `${method}\n${ACCEPT}\n${contentMd5Value}\n${CONTENT_TYPE}\n${date}\n${canonicalHdrs}\n${path}`;
}

function hmacSign(appSecret, canonical) {
  return crypto.createHmac('sha1', appSecret).update(canonical, 'utf8').digest('base64');
}

function rfcDate() {
  return new Date().toUTCString();
}

function uuidUpper() {
  return crypto.randomUUID().toUpperCase();
}

async function callIotGateway(path, params, appKey, appSecret, iotToken, apiVer, baseUrlOverride) {
  apiVer = apiVer || '1.0.0';
  const bodyDict = {
    id: uuidUpper(),
    version: '1.0.0',
    params,
    request: {
      language: 'en-US',
      appKey,
      apiVer,
    },
  };
  if (iotToken) bodyDict.request.iotToken = iotToken;

  const bodyBuffer = Buffer.from(JSON.stringify(bodyDict), 'utf8');
  const md5 = contentMd5(bodyBuffer);
  const timestampMs = String(Date.now());
  const nonce = uuidUpper();
  const date = rfcDate();

  const signHeaders = {
    'x-ca-key': appKey,
    'x-ca-nonce': nonce,
    'x-ca-stage': 'RELEASE',
    'x-ca-timestamp': timestampMs,
    'x-ca-version': '1',
  };
  const canonical = buildCanonical('POST', path, md5, date, signHeaders);
  const signature = hmacSign(appSecret, canonical);
  const sortedKeys = Object.keys(signHeaders).sort();

  const headers = {
    'Content-Type': CONTENT_TYPE,
    Accept: ACCEPT,
    'Content-MD5': md5,
    Date: date,
    'X-Ca-Key': appKey,
    'X-Ca-Nonce': nonce,
    'X-Ca-Timestamp': timestampMs,
    'X-Ca-Stage': 'RELEASE',
    'X-Ca-Version': '1',
    'X-Ca-Signature-Headers': sortedKeys.join(','),
    'X-Ca-Signature-Method': 'HmacSHA1',
    'X-Ca-Signature': signature,
  };

  const url = (baseUrlOverride || BASE_URL) + path;
  const res = await httpRequest('POST', url, headers, bodyBuffer);
  const result = safeJsonParse(res.body);
  if (!result) {
    throw new Error(`HTTP ${res.statusCode}: ${res.body.slice(0, 300)}`);
  }
  if (result.code !== undefined && result.code !== 200) {
    throw new Error(`Alibaba IoT error code=${result.code}: ${JSON.stringify(result).slice(0, 300)}`);
  }
  return result;
}

// ===========================================================================
// Aigostar Smart API (verification code endpoints)
// ===========================================================================

const SMART_API_BASE = 'https://smartapi.aigostar.com';
const PATH_SEND_CODE = '/message/v1.1/security/sendcode/anonymous';

async function smartApiPost(path, body) {
  const url = SMART_API_BASE + path;
  const bodyBuffer = Buffer.from(JSON.stringify(body), 'utf8');
  const headers = Object.assign(
    { 'Content-Type': 'application/json; charset=UTF-8' },
    ucHeaders('POST', url)
  );

  const res = await httpRequest('POST', url, headers, bodyBuffer);
  const result = safeJsonParse(res.body) || {};

  if (res.statusCode >= 400) {
    if (result.code === 'SENDCODE_INTERVAL_IS_TOO_SHORT') {
      // A code was already sent recently; treat as success (it's on its way)
      return { ok: true, alreadySent: true };
    }
    throw new Error(`SmartAPI error: ${JSON.stringify(result)}`);
  }
  return result;
}

async function sendVerificationCode(email) {
  const accountType = email.includes('@') ? 'email' : 'phone_number';
  const body = {
    send_to: email.trim(),
    account_type: accountType,
    action: 'LoginSecurity',
    re_send_count: 0,
    captcha_token: '',
  };
  return smartApiPost(PATH_SEND_CODE, body);
}

// ===========================================================================
// Step 1: UC login -> access_token
// ===========================================================================

class NeedSecurityCodeError extends Error {}

async function ucLogin(email, password, securityCode, deviceId) {
  const encryptedPw = encryptPassword(password);
  const accountType = email.includes('@') ? 'email' : 'phone_number';

  const formParams = {
    account_type: accountType,
    username: email.trim(),
    password: encryptedPw,
    grant_type: 'password',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    cuid: deviceId,
  };
  if (securityCode) formParams.security_code = securityCode;

  const formData = Object.keys(formParams)
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(formParams[k])}`)
    .join('&');

  const loginUrl = UC_BASE + UC_LOGIN;
  const headers = Object.assign(
    { 'Content-Type': 'application/x-www-form-urlencoded' },
    ucHeaders('POST', loginUrl)
  );

  const res = await httpRequest('POST', loginUrl, headers, Buffer.from(formData, 'utf8'));
  const result = safeJsonParse(res.body) || {};

  if (res.statusCode >= 400) {
    if (result.code === 'UC/NEED_SECURITY_CODE') {
      throw new NeedSecurityCodeError(result.message || 'Security code required');
    }
    const msg = result.error_description || result.message || result.error || res.body.slice(0, 300);
    throw new Error(`Login failed: ${msg}`);
  }
  if (!result.access_token) {
    throw new Error(`Login failed: no access_token in response: ${JSON.stringify(result)}`);
  }
  return result;
}

// ===========================================================================
// Step 2: UC authorize -> authCode
// ===========================================================================

async function ucAuthorize(accessToken) {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: SMARTAPP_ID,
    redirect_uri: 'none',
    scope: 'openid profile',
    response_mode: 'json',
  }).toString();
  const authorizeUrl = `${UC_BASE}${UC_AUTHORIZE}?${params}`;
  const headers = Object.assign(
    { Authorization: `Bearer ${accessToken}` },
    ucHeaders('GET', authorizeUrl)
  );

  const res = await httpRequest('GET', authorizeUrl, headers, null);
  const result = safeJsonParse(res.body) || {};
  if (!result.code) {
    throw new Error(`Authorize failed: no code in response: ${JSON.stringify(result)}`);
  }
  return result.code;
}

// ===========================================================================
// Step 3: Region discovery -> OA host
// ===========================================================================

async function resolveOaHost(authCode, appKey, appSecret) {
  try {
    const result = await callIotGateway(
      REGION_API_PATH,
      { type: 'THIRD_AUTHCODE', authCode },
      appKey,
      appSecret,
      null,
      '1.0.2',
      REGION_API_HOST
    );
    const oaHost = (result.data && result.data.oaApiGatewayEndpoint) || '';
    if (oaHost) return oaHost;
  } catch (e) {
    // fall through to fallback
  }
  return OA_HOST_FALLBACK;
}

// ===========================================================================
// Step 4: OAuth login -> sid (OA session)
// ===========================================================================

async function oaLogin(authCode, oaHost, appKey, appSecret) {
  const contentTypeForm = 'application/x-www-form-urlencoded; charset=UTF-8';
  const acceptJson = 'application/json; charset=UTF-8';

  const oauthMap = {
    oauthPlateform: 23,
    accessToken: null,
    openId: null,
    oauthAppKey: appKey,
    tokenType: null,
    authCode,
    userData: null,
  };
  const loginByOauthRequestStr = JSON.stringify(oauthMap);
  const bodyStr = `loginByOauthRequest=${encodeURIComponent(loginByOauthRequestStr)}`;
  const bodyBuffer = Buffer.from(bodyStr, 'utf8');

  const timestampMs = String(Date.now());
  const nonce = uuidUpper();
  const date = rfcDate();

  const signHeaders = {
    'x-ca-key': appKey,
    'x-ca-nonce': nonce,
    'x-ca-stage': 'RELEASE',
    'x-ca-timestamp': timestampMs,
    'x-ca-version': '1',
  };
  const resource = `${OA_LOGIN_PATH}?loginByOauthRequest=${loginByOauthRequestStr}`;

  const sortedKeys = Object.keys(signHeaders).sort();
  const canonicalHdrs = sortedKeys.map((k) => `${k}:${signHeaders[k]}`).join('\n');
  const canonical = `POST\n${acceptJson}\n\n${contentTypeForm}\n${date}\n${canonicalHdrs}\n${resource}`;
  const signature = hmacSign(appSecret, canonical);

  const headers = {
    'Content-Type': contentTypeForm,
    Accept: acceptJson,
    Date: date,
    'X-Ca-Key': appKey,
    'X-Ca-Nonce': nonce,
    'X-Ca-Timestamp': timestampMs,
    'X-Ca-Stage': 'RELEASE',
    'X-Ca-Version': '1',
    'X-Ca-Signature-Headers': sortedKeys.join(','),
    'X-Ca-Signature-Method': 'HmacSHA1',
    'X-Ca-Signature': signature,
  };

  const url = `https://${oaHost}${OA_LOGIN_PATH}`;
  const res = await httpRequest('POST', url, headers, bodyBuffer);
  const result = safeJsonParse(res.body) || {};

  const data = result.data || {};
  const loginData = (data.data && data.data.loginSuccessResult) || {};
  const sid = loginData.sid || '';
  if (!sid) {
    throw new Error(`OA login failed: code=${data.code || '?'}, message=${data.message || ''}`);
  }
  return sid;
}

// ===========================================================================
// Step 5: OA session -> iotToken
// ===========================================================================

async function createSession(sid, appKey, appSecret) {
  const result = await callIotGateway(
    PATH_CREATE_SESSION,
    { request: { authCode: sid, appKey, accountType: 'OA_SESSION' } },
    appKey,
    appSecret,
    null,
    '1.0.4'
  );
  const data = result.data || {};
  if (!data.iotToken) {
    throw new Error(`createSession failed: no iotToken in response: ${JSON.stringify(result)}`);
  }
  return data;
}

// ===========================================================================
// Full login (5 steps)
// ===========================================================================

async function fullLogin(email, password, deviceId, securityCode) {
  const loginInfo = await ucLogin(email, password, securityCode, deviceId);
  const accessToken = loginInfo.access_token;

  const authCode = await ucAuthorize(accessToken);
  const oaHost = await resolveOaHost(authCode, APP_KEY, APP_SECRET);
  const sid = await oaLogin(authCode, oaHost, APP_KEY, APP_SECRET);
  const session = await createSession(sid, APP_KEY, APP_SECRET);
  return session; // { iotToken, refreshToken, identityId, iotTokenExpire, ... }
}

async function refreshIotToken(refreshToken, identityId) {
  // The gateway's /account/* endpoints expect their arguments nested under a
  // `request` object (same shape as createSession, which works). Passing them
  // at the top level makes the gateway reject the call with code 20050
  // ("request required"), which is why the reference integration never got
  // refresh working and always fell back to a full login.
  const result = await callIotGateway(
    PATH_REFRESH,
    { request: { refreshToken, identityId } },
    APP_KEY,
    APP_SECRET,
    null,
    '1.0.4'
  );
  const data = result.data || {};
  if (!data.iotToken) {
    throw new Error(`Token refresh failed: no iotToken in response: ${JSON.stringify(result)}`);
  }
  return data;
}

// ===========================================================================
// Device list & per-device client
// ===========================================================================

async function listDevices(iotToken) {
  const result = await callIotGateway(
    PATH_DEVICES,
    { pageNo: 1, pageSize: 100 },
    APP_KEY,
    APP_SECRET,
    iotToken,
    '1.0.8'
  );
  return (result.data && result.data.data) || [];
}

class AlibabaIoTDevice {
  constructor(iotId, iotToken) {
    this.iotId = iotId;
    this.iotToken = iotToken;
  }

  async getProperties() {
    const result = await callIotGateway(
      PATH_GET,
      { iotId: this.iotId },
      APP_KEY,
      APP_SECRET,
      this.iotToken
    );
    const data = result.data || {};
    const out = {};
    Object.keys(data).forEach((k) => {
      const v = data[k];
      if (v && typeof v === 'object' && 'value' in v) out[k] = v.value;
    });
    return out;
  }

  async setProperties(items) {
    await callIotGateway(
      PATH_SET,
      { iotId: this.iotId, items },
      APP_KEY,
      APP_SECRET,
      this.iotToken
    );
  }
}

// ===========================================================================
// Brightness / color-temperature conversions (Homey <-> Aigostar)
// ===========================================================================

function homeyDimToAigoBrightness(dim) {
  // Homey 'dim' capability: 0.0 - 1.0
  const pct = Math.max(0, Math.min(1, dim));
  return Math.max(1, Math.min(100, Math.round(pct * 100)));
}

function aigoBrightnessToHomeyDim(v) {
  return Math.max(0.01, Math.min(1, v / 100));
}

function homeyTempToAigo(lightTemperature) {
  // Homey 'light_temperature' capability: 0 (cold) - 1 (warm)
  // Aigostar ColorTemperature: 0 (warm) - 100 (cool) -- inverted scale
  const pct = Math.max(0, Math.min(1, lightTemperature));
  return Math.round((1 - pct) * 100);
}

function aigoTempToHomey(v) {
  const pct = Math.max(0, Math.min(100, v)) / 100;
  return 1 - pct;
}

// Homey 'light_hue' (0-1) <-> Aigostar HSVColor.Hue (0-360)
function homeyHueToAigo(hue) {
  const pct = Math.max(0, Math.min(1, hue));
  return Math.round(pct * 360);
}

function aigoHueToHomey(H) {
  return Math.max(0, Math.min(1, Number(H) / 360));
}

// Homey 'light_saturation' (0-1) <-> Aigostar HSVColor.Saturation (0-100)
function homeySatToAigo(sat) {
  const pct = Math.max(0, Math.min(1, sat));
  return Math.round(pct * 100);
}

function aigoSatToHomey(S) {
  return Math.max(0, Math.min(1, Number(S) / 100));
}

module.exports = {
  // login
  fullLogin,
  refreshIotToken,
  sendVerificationCode,
  NeedSecurityCodeError,
  // devices
  listDevices,
  AlibabaIoTDevice,
  // TSL property names
  PROP_SWITCH,
  PROP_BRIGHTNESS,
  PROP_COLOR_TEMP,
  PROP_LIGHT_MODE,
  PROP_HSV,
  // conversions
  homeyDimToAigoBrightness,
  aigoBrightnessToHomeyDim,
  homeyTempToAigo,
  aigoTempToHomey,
  homeyHueToAigo,
  aigoHueToHomey,
  homeySatToAigo,
  aigoSatToHomey,
  KELVIN_WARM,
  KELVIN_COOL,
};
