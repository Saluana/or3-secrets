import { addServerPlugin, createResolver, defineNuxtModule } from '@nuxt/kit';
import type { Nuxt } from '@nuxt/schema';

export default defineNuxtModule({
  meta: { name: '@or3/secrets', configKey: 'or3Secrets' },
  setup(_options: Record<string, never>, nuxt: Nuxt) {
    if (nuxt.options.ssr === false || (nuxt.options as Nuxt['options'] & { _generate?: boolean })._generate) return;
    const config = nuxt.options.runtimeConfig as Record<string, unknown>;
    config.secrets = { provider: '', socketPath: '', tokenFile: '', namespace: '', vaultId: '', ...(config.secrets as object ?? {}) };
    const resolver = createResolver(import.meta.url);
    addServerPlugin(resolver.resolve('runtime/plugin'));
  },
});
