const _ = require('lodash');
const crypto = require('crypto');

class SmartOTP {
  #config = {
    algorithm: 'sha256',
    factor: 5, // seconds
    hexLength: 4,
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
   * @returns timestamp
   */
  #getTimeStamp() {
    const now = new Date();
    return now.getTime();
  }

  /**
   * @param {Integer} timestamp
   * @returns timestamp / factor
   */
  #getOtpChangingParameter(timestamp) {
    const factor = this.#config.factor * 1000;
    return parseInt(timestamp / factor);
  }

  /**
   * @param {Integer} otpChangingParameter
   * @param {String} secret
   * @returns hashed value
   */
  #getHashedValue(otpChangingParameter, secret) {
    const hashedValue = this.#encode(otpChangingParameter.toString() + secret);
    return hashedValue.substr(hashedValue.length - this.#config.hexLength);
  }

  /**
   * @param {String} ascii
   * @returns hash in hex string.
   */
  #encode(ascii) {
    const hash = crypto.createHmac(this.#config.algorithm, ascii);
    hash.update(ascii);
    return hash.digest('hex');
  }

  /**
   * @param {String} secret
   * @returns otp
   */
  generateOtp(secret) {
    const timestamp = this.#getTimeStamp();
    const otpChangingParameter = this.#getOtpChangingParameter(timestamp);
    const hashedValue = this.#getHashedValue(otpChangingParameter, secret);

    let otp = parseInt(hashedValue, 16).toString();
    // hashedValue is hex (16), otp is decimal (10)
    // convert 5 -> 6 characters hex -> decimal return lenght is 6 -> 7
    // we need decrease to 4 hex characters
    // If length is less than 6, add 0 in beginning
    while (otp.length < 6) {
      otp = '0' + otp;
    }
    return otp;
  }

  /**
   * @param {String} value
   * @param {String} secret
   * @returns matches
   */
  matches(value, secret) {
    const otp = this.generateOtp(secret);
    return otp === value;
  }
}

module.exports = SmartOTP;
