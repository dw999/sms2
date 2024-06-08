export interface KEM {
    publicKeyBytes: Promise<number>;
    privateKeyBytes: Promise<number>;
    ciphertextBytes: Promise<number>;
    sharedSecretBytes: Promise<number>;
    keypair: () => Promise<{
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    }>;
    encapsulate: (publicKey: Uint8Array) => Promise<{
        ciphertext: Uint8Array;
        sharedSecret: Uint8Array;
    }>;
    decapsulate: (ciphertext: Uint8Array, privateKey: Uint8Array) => Promise<{
        sharedSecret: Uint8Array;
    }>;
}
declare function kemBuilder(useFallback?: boolean, wasmFilePath?: string | undefined): Promise<KEM>;
export default kemBuilder;
