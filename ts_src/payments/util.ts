import * as bcrypto from '../crypto';
import { Network } from '../networks';
import * as bscript from '../script';
import { Payment, PaymentFunction, Stack, StackFunction } from './index';

export function validColorId(colorId: Buffer, newColorId: Buffer): Buffer {
  if (colorId.length > 0 && !colorId.equals(newColorId))
    throw new TypeError('ColorId mismatch');
  return newColorId;
}

function stacksEqual(a: Buffer[], b: Buffer[]): boolean {
  if (a.length !== b.length) return false;

  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}

export function checkInput(
  chunksFn: StackFunction,
  redeemFn: PaymentFunction,
  hashForCheck: Buffer,
): Buffer | null {
  const chunks = chunksFn();
  if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
  const redeem = redeemFn();
  if (!Buffer.isBuffer(redeem.output)) throw new TypeError('Input is invalid');

  return _checkRedeem(redeem, hashForCheck);
}

export function checkWitness(a: Payment): void {
  if (a.witness) {
    if (
      a.redeem &&
      a.redeem.witness &&
      !stacksEqual(a.redeem.witness, a.witness)
    )
      throw new TypeError('Witness and redeem.witness mismatch');
  }
}

export function checkRedeem(
  a: Payment,
  network: Network,
  redeemFn: PaymentFunction,
  hashForCheck: Buffer,
): void {
  if (a.redeem) {
    if (a.redeem.network && a.redeem.network !== network)
      throw new TypeError('Network mismatch');
    if (a.input) {
      const redeem = redeemFn();
      if (a.redeem.output && !a.redeem.output.equals(redeem.output!))
        throw new TypeError('Redeem.output mismatch');
      if (a.redeem.input && !a.redeem.input.equals(redeem.input!))
        throw new TypeError('Redeem.input mismatch');
    }

    _checkRedeem(a.redeem, hashForCheck);
  }
}

// inlined to prevent 'no-inner-declarations' failing
function _checkRedeem(redeem: Payment, hashForCheck: Buffer): Buffer | null {
  let hash2 = null;
  // is the redeem output empty/invalid?
  if (redeem.output) {
    const decompile = bscript.decompile(redeem.output);
    if (!decompile || decompile.length < 1)
      throw new TypeError('Redeem.output too short');

    // match hash against other sources
    hash2 = bcrypto.hash160(redeem.output);
    if (hashForCheck.length > 0 && !hashForCheck.equals(hash2))
      throw new TypeError('Hash mismatch');
  }

  if (redeem.input) {
    const hasInput = redeem.input.length > 0;
    const hasWitness = redeem.witness && redeem.witness.length > 0;
    if (!hasInput && !hasWitness) throw new TypeError('Empty input');
    if (hasInput && hasWitness)
      throw new TypeError('Input and witness provided');
    if (hasInput) {
      const richunks = bscript.decompile(redeem.input) as Stack;
      if (!bscript.isPushOnly(richunks))
        throw new TypeError('Non push-only scriptSig');
    }
  }
  return hash2;
}
