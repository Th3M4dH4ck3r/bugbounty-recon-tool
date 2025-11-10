# Contributing to Scout

Thank you for your interest in contributing to Scout! This document provides guidelines for contributing to the project.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## How to Contribute

### 1. Fork and Clone

```bash
git clone https://github.com/your-username/scout-security
cd scout-security
npm install
```

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 3. Make Changes

- Follow existing code style
- Add tests for new features
- Update documentation

### 4. Test Your Changes

```bash
npm test
npm run lint
npm run build
```

### 5. Commit

```bash
git add .
git commit -m "feat: add new feature"
```

Use conventional commits:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `refactor:` - Code refactoring

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Development Setup

```bash
npm install
npm run build
npm test
```

## Adding New Features

### Custom Analyzer

Create in `src/analyzers/`:

```typescript
import { Finding } from '../types';

export async function myAnalyzer(code: string): Promise<Finding[]> {
  // Analysis logic
  return [];
}
```

### Custom Rule

Add to `config/rules.yaml`:

```yaml
- id: CUSTOM-XXX
  name: Rule Name
  severity: high
  pattern: 'pattern'
  recommendation: Fix
```

### Custom PoC Template

Add to `src/poc/templates/`:

```typescript
export function generateMyTemplate(finding: Finding): string {
  // Template logic
}
```

## Testing

- Write unit tests for new features
- Aim for >80% coverage
- Test edge cases

```bash
npm test -- --coverage
```

## Documentation

- Update README.md for new features
- Add JSDoc comments to functions
- Update API documentation

## Plugin Development

Create plugins in `src/plugins/`:

```typescript
export interface Plugin {
  name: string;
  analyze: (code: string) => Promise<Finding[]>;
}
```

## Questions?

Open an issue on GitHub or join our Discord.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
