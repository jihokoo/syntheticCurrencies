import { encodeFunctionData } from 'viem';
import type { Hex } from 'viem'

const counterContractAddress = '0xAe63e576eA2361982Ae0E5739c9655438b95abDB' as Hex; // Your deployed contract address
const counterContractAbi = [
    {
        type: 'function',
        name: 'increment',
        inputs: [],
        outputs: [],
        stateMutability: 'nonpayable',
    },
] as const;

export const calls = [
    {
        to: counterContractAddress,
        data: encodeFunctionData({
            abi: counterContractAbi,
            functionName: 'increment',
            args: [],
        }),
        value: 0n, // Use bigint for value
    },
];