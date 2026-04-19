import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  base: '/crypto-lab-ibe-gate/',
  resolve: {
    alias: {
      '@noble/curves/bls12-381.js': path.resolve(
        __dirname,
        'node_modules/@noble/curves/bls12-381.js'
      ),
      '@noble/hashes/sha2.js': path.resolve(
        __dirname,
        'node_modules/@noble/hashes/sha2.js'
      ),
    },
  },
});
