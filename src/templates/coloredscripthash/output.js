'use strict';
// {colorIdentifier} OP_COLOR OP_HASH160 {scriptHash} OP_EQUAL
Object.defineProperty(exports, '__esModule', { value: true });
const bscript = require('../../script');
const script_1 = require('../../script');
function check(script) {
  const buffer = bscript.compile(script);
  return (
    buffer.length === 58 &&
    buffer[0] === 0x21 &&
    buffer[34] === script_1.OPS.OP_COLOR &&
    buffer[35] === script_1.OPS.OP_HASH160 &&
    buffer[36] === 0x14 &&
    buffer[57] === script_1.OPS.OP_EQUAL
  );
}
exports.check = check;
check.toJSON = () => {
  return 'colored scriptHash output';
};
