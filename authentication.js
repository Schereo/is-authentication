import axios from 'axios';
import * as ed from '@noble/ed25519';
import bs58 from 'bs58';
import crypto from 'crypto';

const requestNonce = async (identityId) => {
  const url = `http://localhost:3000/api/v0.1/authentication/prove-ownership/${identityId}`;
  const request = await axios.get(url);
  return request.data.nonce;
};

const hashNonce = (nonce) => {
  const hashedNonce = crypto.createHash('sha256').update(nonce).digest('hex');
  return hashedNonce;
};

const signNonce = async (hashedNonce, secretKey) => {
  const encodedSecretKey = bs58.decode(secretKey).toString('hex');
  const signedNonceArray = await ed.sign(hashedNonce, encodedSecretKey);
  const signedNonce = ed.Signature.fromHex(signedNonceArray).toHex();
  return signedNonce;
};

const requestJWT = async (identityId, signedNonce) => {
  const body = { signedNonce };
  const url = `http://localhost:3000/api/v0.1/authentication/prove-ownership/${identityId}`;
  const request = await axios.post(url, body);
  return request.data.jwt;
};

const setAxiosHeader = (jwt) => {
  axios.defaults.headers.common['Authorization'] = `Bearer ${jwt}`;
};

const authenticate = async (identityId, secretKey) => {
  const nonce = await requestNonce(identityId);
  const hashedNonce = hashNonce(nonce);
  const signedNonce = await signNonce(hashedNonce, secretKey);
  const jwt = await requestJWT(identityId, signedNonce);
  setAxiosHeader(jwt);
  console.log('JWT: ', jwt);
};

const identityId = 'did:iota:8BAmUqAg4aUjV3T9WUhPpDnFVbJSk16oLyFq3m3e62MF';
const secretKey = '5N3SxG4UzVDpNe4LyDoZyb6bSgE9tk3pE2XP5znXo5bF';
authenticate(identityId, secretKey);
