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
			head: [
				{
					tag: 'link',
					attrs: {
						rel: 'preconnect',
						href: 'https://fonts.googleapis.com',
					},
				},
				{
					tag: 'link',
					attrs: {
						rel: 'preconnect',
						href: 'https://fonts.gstatic.com',
						crossorigin: true,
					},
				},
				{
					tag: 'link',
					attrs: {
						rel: 'stylesheet',
						href: 'https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&display=swap',
					},
				},
				{
					tag: 'style',
					content: 'code, pre, pre code, .expressive-code code { font-family: "Fira Code", monospace !important; }',
				},
			],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Configuration', slug: 'getting-started/configuration' },
						{ label: 'Docker Deployment', slug: 'getting-started/docker' },
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
