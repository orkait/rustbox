// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import catppuccin from 'starlight-theme-catppuccin';

export default defineConfig({
	site: 'https://rustbox.orkait.com',
	integrations: [
		starlight({
			title: 'rustbox',
			tagline: 'Kernel-enforced sandboxing for untrusted code execution',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/orkait/rustbox' }],
			plugins: [
				catppuccin({ dark: 'mocha-peach', light: 'latte-peach' }),
			],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Installation & Quickstart', slug: 'getting-started' },
						{ label: 'Configuration', slug: 'getting-started/configuration' },
					],
				},
				{
					label: 'API Reference',
					items: [
						{ label: 'Overview', slug: 'api' },
						{ label: 'POST /api/submit', slug: 'api/submit' },
						{ label: 'GET /api/result/{id}', slug: 'api/result' },
						{ label: 'Webhooks', slug: 'api/webhooks' },
						{ label: 'Health & Languages', slug: 'api/health' },
					],
				},
				{
					label: 'Architecture',
					items: [
						{ label: 'Overview', slug: 'architecture' },
						{ label: 'Isolation Model', slug: 'architecture/isolation' },
						{ label: 'Typestate Chain', slug: 'architecture/typestate' },
						{ label: 'Verdict System', slug: 'architecture/verdict' },
						{ label: 'Execution Lifecycle', slug: 'architecture/lifecycle' },
					],
				},
				{
					label: 'Internals',
					items: [
						{ label: 'Seccomp', slug: 'internals/seccomp' },
						{ label: 'Cgroups', slug: 'internals/cgroups' },
						{ label: 'Testing', slug: 'internals/testing' },
					],
				},
			],
		}),
	],
});
