const _ = require('lodash');
const crypto = require('crypto');

// base64 vs base64Url: https://stackoverflow.com/a/55389212
const TEXT_ENCODING = 'base64url';

class Jwt {
  #config = {
    secret: '',
  };

  /**
   * @param {Object} config
   */
  constructor(_config) {
    this.#init(_config);
  }

  /**
   * @param {Object} _config
   */
  #init(_config) {
    if (_.isEmpty(_config)) {
      return;
    }
    if (!_.isObject(_config)) {
      throw 'Config must be an Object !';
    }
    const config = _.pick(_config, _.keys(this.#config));
    _.forEach(config, (value, key) => {
      this.#config[key] = value;
    });
  }

  /**
   * @param {Object} obj
   * @returns {String} base64url
   */
  encode(obj) {
    // converts the obj to a string
    const str = JSON.stringify(obj);
    // returns string converted to base64
    return Buffer.from(str).toString(TEXT_ENCODING);
  }

  /**
   * @param {String} token
   * @returns {Object} token decoded
   */
  decode(token) {
    const [headerEncoded, payloadEncoded] = _.split(token, '.');
    return { headerEncoded, payloadEncoded };
  }

  /**
   * @param {Object} payload
   * @returns {Object} new payload
   */
  getPayload(payload) {
    return {
      ...payload,
      iss: _.get(payload, 'iss', 'Bach beo'),
      exp: _.get(payload, 'exp', 86400) * 1000, // milliseconds
    };
  }

  /**
   * @param {Object} header
   * @param {Object} payload
   * @returns {String} signature
   */
  createSignature(header, payload) {
    // create a HMAC(hash based message authentication code) using sha256 hashing alg
    let signature = crypto.createHmac('sha256', this.#config.secret);
    // use the update method to hash a string formed from our jwtB64Header a period and jwtB64Payload
    signature.update(header + '.' + payload);
    // signature needs to be converted to base64url to make it usable
    return signature.digest(TEXT_ENCODING);
  }

  /**
   * @param {Object} payload (read more: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1)
   * @returns {String} json web token
   */
  generateToken(payload) {
    const headerEncoded = this.encode({
      alg: 'HS256',
      typ: 'JWT',
    });
    const newPayload = this.getPayload(payload);
    const payloadEncoded = this.encode(newPayload);
    return this._generateToken(headerEncoded, payloadEncoded);
  }

  /**
   * @param {String} headerEncoded
   * @param {String} payloadEncoded
   * @returns json web token
   */
  _generateToken(headerEncoded, payloadEncoded) {
    const signature = this.createSignature(headerEncoded, payloadEncoded);
    return headerEncoded + '.' + payloadEncoded + '.' + signature;
  }

  /**
   * @param {String} value
   * @returns matches
   */
  matches(token) {
    const { headerEncoded, payloadEncoded } = this.decode(token);
    const validToken = this._generateToken(headerEncoded, payloadEncoded);
    return token === validToken;
  }
}

module.exports = Jwt;
