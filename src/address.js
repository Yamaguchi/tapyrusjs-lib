'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const networks = require('./networks');
const payments = require('./payments');
const bscript = require('./script');
const types = require('./types');
const bs58check = require('bs58check');
const typeforce = require('typeforce');
function fromBase58Check(address) {
  const payload = bs58check.decode(address);
  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < 21) throw new TypeError(address + ' is too short');
  if (payload.length > 21) throw new TypeError(address + ' is too long');
  const version = payload.readUInt8(0);
  const hash = payload.slice(1);
  return { version, hash };
}
exports.fromBase58Check = fromBase58Check;
function toBase58Check(hash, version) {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments);
  const payload = Buffer.allocUnsafe(21);
  payload.writeUInt8(version, 0);
  hash.copy(payload, 1);
  return bs58check.encode(payload);
}
exports.toBase58Check = toBase58Check;
function fromOutputScript(output, network) {
  try {
    const payment = payments.util.fromOutputScript(output, network);
    return payment.address;
  } catch (e) {}
  throw new Error(bscript.toASM(output) + ' has no matching Address');
}
exports.fromOutputScript = fromOutputScript;
function toOutputScript(address, network) {
  network = network || networks.prod;
  let decodeBase58;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}
  if (decodeBase58) {
    if (decodeBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodeBase58.hash }).output;
    if (decodeBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodeBase58.hash }).output;
    if (decodeBase58.version === network.coloredPubKeyHash)
      return payments.cp2pkh({ hash: decodeBase58.hash }).output;
    if (decodeBase58.version === network.coloredScriptHash)
      return payments.cp2sh({ hash: decodeBase58.hash }).output;
  }
  throw new Error(address + ' has no matching Script');
}
exports.toOutputScript = toOutputScript;
