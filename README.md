# Setup

```
$ npm i
```

# Example

## Init

```js
const { SmartOTP, Jwt } = require('bach-utils');
const secret = 'okay';
```

## Smart OTP

```js
const smartOTP = new SmartOTP({
  factor: 100,
});
const otp = smartOTP.generateOtp(secret);
const matches = smartOTP.matches(otp, secret);
console.log('otp', otp);
console.log('matches', matches);
```

## JWT

```js
const jwt = new Jwt({
  secret,
});
const token = jwt.generateToken({
  user: 'Bach beo',
});
console.log('token', token);
console.log('matches', jwt.matches(token));
```
