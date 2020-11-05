'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const bcrypto = require('../crypto');
const networks_1 = require('../networks');
const bscript = require('../script');
const lazy = require('./lazy');
const util_1 = require('./util');
const typef = require('typeforce');
const OPS = bscript.OPS;
const bs58check = require('bs58check');
// input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: {colorId} OP_COLOR OP_HASH160 {hash160(redeemScript)} OP_EQUAL
function cp2sh(a, opts) {
  if (!a.address && !a.hash && !a.output && !a.redeem && !a.input)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  typef(
    {
      network: typef.maybe(typef.Object),
      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(58)),
      redeem: typef.maybe({
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.Buffer),
        input: typef.maybe(typef.Buffer),
        witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      }),
      input: typef.maybe(typef.Buffer),
      witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      colorId: typef.maybe(typef.BufferN(33)),
    },
    a,
  );
  let network = a.network;
  if (!network) {
    network = (a.redeem && a.redeem.network) || networks_1.prod;
  }
  const o = { network };
  const _address = lazy.value(() => {
    const payload = bs58check.decode(a.address);
    const version = payload.readUInt8(0);
    const colorId = payload.slice(1, 34);
    const hash = payload.slice(34);
    return { version, colorId, hash };
  });
  const _chunks = lazy.value(() => {
    return bscript.decompile(a.input);
  });
  const _redeem = lazy.value(() => {
    const chunks = _chunks();
    return {
      network,
      output: chunks[chunks.length - 1],
      input: bscript.compile(chunks.slice(0, -1)),
      witness: a.witness || [],
    };
  });
  // output dependents
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    if (!o.colorId) return;
    const payload = Buffer.allocUnsafe(54);
    payload.writeUInt8(o.network.coloredScriptHash, 0);
    o.colorId.copy(payload, 1);
    o.hash.copy(payload, 34);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    // in order of least effort
    if (a.output) return a.output.slice(37, 57);
    if (a.address) return _address().hash;
    if (o.redeem && o.redeem.output) return bcrypto.hash160(o.redeem.output);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    if (!o.colorId) return;
    return bscript.compile([
      o.colorId,
      OPS.OP_COLOR,
      OPS.OP_HASH160,
      o.hash,
      OPS.OP_EQUAL,
    ]);
  });
  // input dependents
  lazy.prop(o, 'redeem', () => {
    if (!a.input) return;
    return _redeem();
  });
  lazy.prop(o, 'input', () => {
    if (!a.redeem || !a.redeem.input || !a.redeem.output) return;
    return bscript.compile(
      [].concat(bscript.decompile(a.redeem.input), a.redeem.output),
    );
  });
  lazy.prop(o, 'witness', () => {
    if (o.redeem && o.redeem.witness) return o.redeem.witness;
    if (o.input) return [];
  });
  lazy.prop(o, 'name', () => {
    const nameParts = ['cp2sh'];
    if (o.redeem !== undefined && o.redeem.name !== undefined)
      nameParts.push(o.redeem.name);
    return nameParts.join('-');
  });
  lazy.prop(o, 'colorId', () => {
    if (a.output) return a.output.slice(1, 34);
    if (a.address) return _address().colorId;
  });
  if (opts.validate) {
    let hash = Buffer.from([]);
    let colorId = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.coloredScriptHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      if (_address().colorId.length !== 33)
        throw new TypeError('Invalid address');
      hash = _address().hash;
      colorId = _address().colorId;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.colorId) {
      colorId = util_1.validColorId(colorId, a.colorId);
    }
    if (a.output) {
      if (
        a.output.length !== 58 ||
        a.output[0] !== 0x21 ||
        a.output[34] !== OPS.OP_COLOR ||
        a.output[35] !== OPS.OP_HASH160 ||
        a.output[36] !== 0x14 ||
        a.output[57] !== OPS.OP_EQUAL
      )
        throw new TypeError('Output is invalid');
      const colorId2 = a.output.slice(1, 34);
      util_1.validColorId(colorId, colorId2);
      const hash2 = a.output.slice(37, 57);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }
    if (a.input) {
      const hash2 = util_1.checkInput(_chunks, _redeem, hash);
      if (hash2) {
        hash = hash2;
      }
    }
    util_1.checkRedeem(a, network, _redeem, hash);
    util_1.checkWitness(a);
  }
  return Object.assign(o, a);
}
exports.cp2sh = cp2sh;
