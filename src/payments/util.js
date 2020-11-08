'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const bcrypto = require('../crypto');
const bscript = require('../script');
const lazy = require('./lazy');
function chunksFn(script) {
  return lazy.value(() => {
    return bscript.decompile(script);
  });
}
exports.chunksFn = chunksFn;
function redeemFn(a, network) {
  return lazy.value(() => {
    const chunks = chunksFn(a.input)();
    return {
      network,
      output: chunks[chunks.length - 1],
      input: bscript.compile(chunks.slice(0, -1)),
      witness: a.witness || [],
    };
  });
}
exports.redeemFn = redeemFn;
function checkHash(hash, hash2) {
  if (hash.length > 0 && !hash.equals(hash2))
    throw new TypeError('Hash mismatch');
}
exports.checkHash = checkHash;
function validColorId(colorId, newColorId) {
  if (colorId.length > 0 && !colorId.equals(newColorId))
    throw new TypeError('ColorId mismatch');
  return newColorId;
}
exports.validColorId = validColorId;
function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
exports.stacksEqual = stacksEqual;
function checkInput(_chunksFn, _redeemFn, hashForCheck) {
  const chunks = _chunksFn();
  if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
  const redeem = _redeemFn();
  if (!Buffer.isBuffer(redeem.output)) throw new TypeError('Input is invalid');
  return _checkRedeem(redeem, hashForCheck);
}
exports.checkInput = checkInput;
function checkWitness(a) {
  if (a.witness) {
    if (
      a.redeem &&
      a.redeem.witness &&
      !stacksEqual(a.redeem.witness, a.witness)
    )
      throw new TypeError('Witness and redeem.witness mismatch');
  }
}
exports.checkWitness = checkWitness;
function checkRedeem(a, network, _redeemFn, hashForCheck) {
  if (a.redeem) {
    if (a.redeem.network && a.redeem.network !== network)
      throw new TypeError('Network mismatch');
    if (a.input) {
      const redeem = _redeemFn();
      if (a.redeem.output && !a.redeem.output.equals(redeem.output))
        throw new TypeError('Redeem.output mismatch');
      if (a.redeem.input && !a.redeem.input.equals(redeem.input))
        throw new TypeError('Redeem.input mismatch');
    }
    _checkRedeem(a.redeem, hashForCheck);
  }
}
exports.checkRedeem = checkRedeem;
// inlined to prevent 'no-inner-declarations' failing
function _checkRedeem(redeem, hashForCheck) {
  let hash2 = null;
  // is the redeem output empty/invalid?
  if (redeem.output) {
    const decompile = bscript.decompile(redeem.output);
    if (!decompile || decompile.length < 1)
      throw new TypeError('Redeem.output too short');
    // match hash against other sources
    hash2 = bcrypto.hash160(redeem.output);
    checkHash(hashForCheck, hash2);
  }
  if (redeem.input) {
    const hasInput = redeem.input.length > 0;
    const hasWitness = redeem.witness && redeem.witness.length > 0;
    if (!hasInput && !hasWitness) throw new TypeError('Empty input');
    if (hasInput && hasWitness)
      throw new TypeError('Input and witness provided');
    if (hasInput) {
      const richunks = bscript.decompile(redeem.input);
      if (!bscript.isPushOnly(richunks))
        throw new TypeError('Non push-only scriptSig');
    }
  }
  return hash2;
}
