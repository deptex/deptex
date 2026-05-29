import {
    SiNextdotjs, SiReact, SiVuedotjs, SiNodedotjs, SiNuxt, SiSvelte, SiAngular, SiExpress,
    SiPython, SiDjango, SiFastapi, SiFlask,
    SiOpenjdk, SiSpringboot, SiQuarkus, SiAndroid,
    SiGo, SiGin,
    SiRust, SiActix, SiRocket,
    SiDotnet,
    SiRuby, SiRubyonrails, SiRubysinatra,
    SiPhp, SiLaravel, SiSymfony, SiWordpress,
    SiDart, SiFlutter,
    SiElixir,
    SiSwift,
    SiTerraform, SiKubernetes, SiDocker, SiHelm, SiServerless, SiGithubactions,
} from '@icons-pack/react-simple-icons';
import { Cloud, FileCode } from 'lucide-react';

const icons: Record<string, React.ComponentType<{ size?: number; className?: string; title?: string }>> = {
    nextjs: SiNextdotjs,
    'create-react-app': SiReact,
    react: SiReact,
    vue: SiVuedotjs,
    nuxt: SiNuxt,
    svelte: SiSvelte,
    angular: SiAngular,
    express: SiExpress,
    node: SiNodedotjs,
    javascript: SiNodedotjs,
    npm: SiNodedotjs,
    python: SiPython,
    pypi: SiPython,
    django: SiDjango,
    fastapi: SiFastapi,
    flask: SiFlask,
    java: SiOpenjdk,
    maven: SiOpenjdk,
    'spring-boot': SiSpringboot,
    quarkus: SiQuarkus,
    android: SiAndroid,
    go: SiGo,
    golang: SiGo,
    gin: SiGin,
    echo: SiGo,
    fiber: SiGo,
    rust: SiRust,
    cargo: SiRust,
    actix: SiActix,
    axum: SiRust,
    rocket: SiRocket,
    dotnet: SiDotnet,
    nuget: SiDotnet,
    aspnet: SiDotnet,
    ruby: SiRuby,
    gem: SiRuby,
    rails: SiRubyonrails,
    sinatra: SiRubysinatra,
    php: SiPhp,
    composer: SiPhp,
    laravel: SiLaravel,
    symfony: SiSymfony,
    wordpress: SiWordpress,
    dart: SiDart,
    flutter: SiFlutter,
    elixir: SiElixir,
    swift: SiSwift,

    // IaC frameworks. Brand icons where Simple Icons ships them; generic
    // lucide-react glyphs as placeholders for AWS/Azure-derived formats
    // which Simple Icons no longer publishes.
    terraform: SiTerraform,
    kubernetes: SiKubernetes,
    dockerfile: SiDocker,
    helm: SiHelm,
    serverless: SiServerless,
    github_actions: SiGithubactions,
    cloudformation: Cloud,
    arm: Cloud,
    bicep: FileCode,
} as Record<string, React.ComponentType<{ size?: number; className?: string; title?: string }>>;

export function FrameworkIcon({ frameworkId, size = 20, className }: { frameworkId?: string | null; size?: number; className?: string }) {
    const Icon = frameworkId ? icons[frameworkId] : null;

    if (!Icon) {
        return <img src="/images/logo_white.png" alt="Project" style={{ width: size, height: size }} className={className} />;
    }

    return <Icon size={size} className={className || "text-white"} title="" />;
}
