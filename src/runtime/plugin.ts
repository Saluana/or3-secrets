import { defineNitroPlugin } from 'nitropack/runtime/plugin';
import { useRuntimeConfig } from '#imports';
import { registerSecretStore } from '~~/server/secrets/registry';
import { createClient, SecretError } from '../client.js';

export default defineNitroPlugin(() => {
  const config = useRuntimeConfig().secrets;
  if (
    config?.provider === 'or3-secrets' &&
    (!config.namespace || !config.socketPath || !config.tokenFile || !config.vaultId)
  )
    throw new SecretError('invalid_configuration');
  registerSecretStore({
    id: 'or3-secrets',
    create: () => {
      if (!config) throw new SecretError('invalid_configuration');
      const client = createClient({
        socketPath: config.socketPath,
        tokenFile: config.tokenFile,
        vaultId: config.vaultId,
        ...(config.serviceUid === '' || config.serviceUid === undefined
          ? {}
          : { serviceUid: Number(config.serviceUid) }),
      });
      return {
        ...client,
        available: async (context?: Parameters<typeof client.status>[0]) => {
          await client.probe(context);
        },
      };
    },
  });
});
