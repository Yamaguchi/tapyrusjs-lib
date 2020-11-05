import { Network } from '../networks';
import { Payment, PaymentFunction, StackFunction } from './index';
export declare function validColorId(colorId: Buffer, newColorId: Buffer): Buffer;
export declare function checkInput(chunksFn: StackFunction, redeemFn: PaymentFunction, hashForCheck: Buffer): Buffer | null;
export declare function checkWitness(a: Payment): void;
export declare function checkRedeem(a: Payment, network: Network, redeemFn: PaymentFunction, hashForCheck: Buffer): void;
