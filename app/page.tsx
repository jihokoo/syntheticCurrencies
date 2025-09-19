"use client";
import Image from "next/image";
import styles from "./page.module.css";
import { Wallet } from "@coinbase/onchainkit/wallet";
// @noErrors: 2307 - Cannot find module '@/calls'
import { Transaction } from '@coinbase/onchainkit/transaction';
import { calls } from './calls';

export default function Home() {
  return (
    <main className="flex flex-grow items-center justify-center">
      <div className={styles.container}>
        <header className={styles.headerWrapper}>
          <Wallet />
        </header>

        <div className={styles.content}>
          <h1>Convert Crypto to wrapped KRW/JPY/RMB</h1>
          <p>KRW/JPY/RMB stable coins are banned by their respective issuers! My family runs a business where the friction of moving FX is time-consuming and costly. But what about swaps with wrapped versions of the currency or an over collateralized borrowing model like AAVE and $GHO? While an incomplete implementation, I wanted to explore recent developments in the blockchain with this project.</p>
          <Image
            priority
            src="/sphere.svg"
            alt="Sphere"
            width={200}
            height={200}
          />

          <div className="w-full max-w-4xl p-4">
            <div className="mx-auto mb-6 w-1/3">
              <Transaction calls={calls} />
            </div>
          </div>
        </div>
      </div>
    </main >
  );
}
