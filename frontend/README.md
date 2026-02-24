# Deptex Frontend

A developer- and security-first platform for managing open source dependencies across projects and teams.

## Overview

Deptex is a dependency governance platform that helps organizations:
- Track dependencies (direct + transitive) with GitHub integration
- Enforce policy-as-code (licenses, vulnerabilities, source policies)
- Collaborate via Watchlists and approval workflows
- Get smart alerts with AI-powered remediation
- Generate SBOM exports and compliance reports

## Architecture

- `/app` — application routes and pages
- `/components` — UI building blocks (ShadCN-based)
- `/lib` — helpers, utilities, API clients
- `/hooks` — custom React hooks
- `/types` — shared TypeScript types

## Tech Stack

- **React 18** with TypeScript
- **Vite** for build tooling
- **Tailwind CSS** for styling
- **React Router** for routing
- **Radix UI** for accessible components
- **ShadCN UI** component library

## Color Palette

The application uses a custom dark theme color scheme:

### Primary Brand
- **Primary Green**: `#025230` - Main accent color for buttons and interactive elements

### Backgrounds
- **Darkest Background**: `#0D0F12` - Main canvas
- **Card Background**: `#1A1C1E` - Cards and panels
- **Subtle Gray**: `#2C3138` - Borders and dividers

### Text Colors
- **Primary Text**: `#F0F4F8` - Main content
- **Secondary Text**: `#A0A6AD` - Labels and helper text
- **Muted Text**: `#6C757D` - Placeholders and disabled states

### Status Colors
- **Success**: `#4CAF50`
- **Warning**: `#FFC107`
- **Error**: `#EF5350`
- **Info**: `#2196F3`

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or yarn

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

The app will be available at `http://localhost:3000`

### Build

```bash
npm run build
```

### Preview Production Build

```bash
npm run preview
```

## Project Structure

```
src/
├── app/
│   ├── App.tsx          # Main app component
│   ├── Main.css         # Global styles
│   ├── routes.tsx       # Route configuration
│   └── pages/           # Page components
├── components/
│   ├── ui/              # Reusable UI components
│   └── NavBar/          # Navigation component
├── hooks/               # Custom React hooks
├── lib/                 # Utilities and helpers
└── types/               # TypeScript type definitions
```

## Deployments

- Preview deployments: Vercel
- Production: Vercel (main branch)

## Contributing

Internal repo — please follow commit conventions and PR workflow.

## License

Private — all rights reserved.
