'use strict';
// {colorIdentifier} OP_COLOR OP_DUP OP_HASH160 {pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG
Object.defineProperty(exports, '__esModule', { value: true });
const bscript = require('../../script');
const script_1 = require('../../script');
function check(script) {
  const buffer = bscript.compile(script);
  return (
    buffer.length === 60 &&
    buffer[0] === 0x21 &&
    buffer[34] === script_1.OPS.OP_COLOR &&
    buffer[35] === script_1.OPS.OP_DUP &&
    buffer[36] === script_1.OPS.OP_HASH160 &&
    buffer[37] === 0x14 &&
    buffer[58] === script_1.OPS.OP_EQUALVERIFY &&
    buffer[59] === script_1.OPS.OP_CHECKSIG
  );
}
exports.check = check;
check.toJSON = () => {
  return 'colored pubKeyHash output';
};
