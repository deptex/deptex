const ECOSYSTEM_DEFAULTS: Record<string, string> = {
    npm: 'node',
    pypi: 'python',
    maven: 'java',
    nuget: 'dotnet',
    golang: 'go',
    cargo: 'rust',
    gem: 'ruby',
    composer: 'php',
    pub: 'dart',
    hex: 'elixir',
    swift: 'swift',
};

export function detectFramework(dependencies: Record<string, string>, ecosystem?: string) {
    if (!ecosystem || ecosystem === 'npm') {
        const deps = Object.keys(dependencies);

        if (deps.includes('next')) return 'nextjs';
        if (deps.includes('react-scripts')) return 'create-react-app';
        if (deps.includes('react') && deps.includes('react-dom')) return 'react';
        if (deps.includes('vue')) return 'vue';
        if (deps.includes('nuxt')) return 'nuxt';
        if (deps.includes('svelte')) return 'svelte';
        if (deps.includes('@angular/core')) return 'angular';
        if (deps.includes('express')) return 'express';

        return 'unknown';
    }

    return ECOSYSTEM_DEFAULTS[ecosystem] || 'unknown';
}
