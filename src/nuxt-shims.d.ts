declare module '#imports' {
  export function defineNitroPlugin(plugin: () => void): () => void;
  export function useRuntimeConfig(): {
    secrets?: {
      provider: string;
      socketPath: string;
      tokenFile: string;
      namespace: string;
      vaultId: string;
      serviceUid?: number | string;
    };
  };
}
declare module '~~/server/secrets/registry' {
  export function registerSecretStore(item: {
    id: string;
    create: () => import('./protocol.js').SecretStore & {
      available(context?: Partial<import('./protocol.js').Context>): Promise<void>;
    };
  }): void;
}

declare module 'nitropack/runtime/plugin' {
  export function defineNitroPlugin(plugin: () => void): () => void;
}
