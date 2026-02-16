# AGENTS.md — samlify

> High-level SAML 2.0 library for Node.js (SSO, SLO, metadata, bindings).
> TypeScript 4.4+, targets ES5/CommonJS. Output in `build/`, declarations in `types/`.

## Repo Context

This is a **private fork** (`robelest/samlify`) of `tngan/samlify`.
**Never push to upstream.** Upstream is fetch/rebase/reference only.

An edge-runtime-compatible rewrite is planned. Read
`docs/EDGE_RUNTIME_PARITY_PLAN.md` for the full milestone plan, workspace
architecture, dependency strategy, and security/compatibility contracts.
Key constraints from that plan:
- Do not introduce Node builtin dependencies into runtime packages.
- Prefer Oslo (`@oslojs/*`) + WebCrypto (`crypto.subtle`) primitives.
- Follow the milestone order (M0-M11) and pass all CI/security gates per milestone.

## Build & Run Commands

```bash
# Install dependencies
bun install

# Build (clean + compile)
make rebuild            # rm -rf build && tsc

# Lint (legacy TSLint)
bun run lint            # tslint -p .
bun run lint:fix        # tslint -p . --fix

# Run all tests
bun run test            # NODE_ENV=test vitest run

# Run tests in watch mode
bun run test:watch      # NODE_ENV=test vitest

# Run a single test file
bunx vitest run test/flow.ts
bunx vitest run test/index.ts

# Run a single test by name pattern
bunx vitest run -t "base64 encoding"
bunx vitest run test/index.ts -t "base64 encoding"

# Coverage
bun run coverage        # vitest run --coverage
```

**Pre-test step:** `make pretest` copies `test/key/` and `test/misc/` into `build/test/`.
This runs automatically via the `pretest` script in package.json.

**CI note:** The XSD schema validator (`@authenio/samlify-xsd-schema-validator`) requires
a Java JDK at runtime. Tests that use it will skip or fail without Java installed.

## Project Structure

```
index.ts              Main barrel export
src/                  Source code (17 files)
  entity.ts           Base Entity class (IdP/SP abstraction)
  entity-idp.ts       IdentityProvider implementation
  entity-sp.ts        ServiceProvider implementation
  flow.ts             SAML flow orchestration (redirect, post, simpleSign)
  libsaml.ts          Core library (signing, verification, encryption)
  metadata.ts         Base Metadata class
  metadata-idp.ts     IdP metadata
  metadata-sp.ts      SP metadata
  extractor.ts        XML data extraction via XPath
  types.ts            TypeScript type definitions
  urn.ts              SAML URN constants and enums
  utility.ts          Utility functions (base64, deflate, cert parsing)
  validator.ts        Time/clock-drift validation
  binding-post.ts     HTTP-POST binding
  binding-redirect.ts HTTP-Redirect binding
  binding-simplesign.ts HTTP-POST-SimpleSign binding
  api.ts              Global context (schema validator, DOM parser)
test/                 Test suite (Vitest)
  index.ts            Unit tests (utility, crypto, metadata)
  flow.ts             Integration tests (full SSO/SLO flows)
  extractor.ts        XML extractor tests
  issues.ts           Regression tests for GitHub issues
  key/                Test certificates and private keys
  misc/               XML fixture files (metadata, requests, responses)
```

## Test Framework

- **Vitest** v1 with `environment: 'node'` and `globals: true`.
- Test files live in `test/` as plain `.ts` files (not `.test.ts` or `.spec.ts`).
- Import vitest directly: `import { test, expect } from 'vitest'`.
- Use `test.sequential()` for tests that manipulate time (via `timekeeper`).
- Use `test.skip()` for known-broken tests.
- Fixtures are read with `readFileSync` from `./test/key/` and `./test/misc/`.

## Code Style

### Formatting
- **2-space indentation** for all TS/JS/JSON/HTML/CSS files (`.editorconfig`).
- **Single quotes** for strings (TSLint enforced; avoid template literals when unnecessary).
- **No trailing commas**.
- **LF line endings**, UTF-8 charset.
- Arrow functions omit parens for single args: `x => x.toString()`.
- No max line length enforced.

### File & Module Naming
- **Files:** kebab-case (`binding-post.ts`, `entity-idp.ts`, `metadata-sp.ts`).
- **Modules export** a default factory function + named class export:
  ```typescript
  export default function(props) { return new IdentityProvider(props); }
  export class IdentityProvider extends Entity { ... }
  ```

### Naming Conventions
- **Classes:** PascalCase (`Entity`, `IdentityProvider`, `ServiceProvider`).
- **Interfaces/Types:** PascalCase, no `I` prefix (`MetadataInterface`, `EntitySetting`, `ESamlHttpRequest`).
- **Enums:** PascalCase name and members (`BindingNamespace.Redirect`, `StatusCode.Success`).
- **Functions/methods:** camelCase (`createLoginRequest`, `verifySignature`).
- **Variables:** camelCase; leading underscore allowed for private/internal (`_spPrivPem`).
- **Constants:** camelCase for object constants (`defaultEntitySetting`, `signatureAlgorithms`).

### Types
- Interfaces and type aliases used interchangeably; prefer `interface` for object shapes
  with optional fields, `type` for unions and aliases.
- `any` is used in legacy code — avoid introducing new `any` types where possible.
- Union types for flexible inputs: `string | Buffer`, `string | string[]`.
- Index signatures: `{ [key: string]: any }`.
- `strictNullChecks` is enabled in tsconfig.

### Imports
- **Named imports** preferred: `import { isString, isNonEmptyArray } from './utility'`.
- **Default imports** for module classes: `import libsaml from './libsaml'`.
- **Star imports** for Node builtins and some libs: `import * as uuid from 'uuid'`.
- No enforced import ordering (TSLint `ordered-imports` is off).

### Documentation
- JSDoc-style comments on public methods with `@desc`, `@param`, `@return`.
- File headers: `@file filename.ts` and `@author`.

### Error Handling
- Throw errors with uppercase snake-case codes: `throw new Error('ERR_EMPTY_METADATA')`.
- Promise rejections use string codes: `Promise.reject('ERR_REDIRECT_FLOW_BAD_ARGS')`.
- Error code prefix is always `ERR_` followed by `UPPER_SNAKE_CASE`.
- Use `console.warn()` for non-fatal warnings, `console.error()` for encryption failures.
- Try/catch blocks around crypto and XML operations; re-throw on unrecoverable errors.

### Patterns
- Spread operator for config merging: `{ ...defaultEntitySetting, ...props }`.
- `Object.assign` occasionally used in older code alongside spread.
- Factory functions as default exports that wrap `new Class(props)`.
- Revealing module pattern in `libsaml.ts`.

## TypeScript Configuration

Key compiler options:
- `target: "es5"`, `module: "commonjs"`, `moduleResolution: "node"`
- `strictNullChecks: true`
- `esModuleInterop: true`
- `declaration: true` (emits to `types/`)
- `experimentalDecorators: true`, `emitDecoratorMetadata: true`
- `downlevelIteration: true`
- Output: `build/`

## TSLint Rules (Legacy)

The project uses TSLint (deprecated) with `tslint:recommended` extended. Key overrides:
- `arrow-parens`: ban single-arg parens
- `quotemark`: single quotes, avoid-escape, avoid-template
- `variable-name`: ban-keywords, check-format, allow-leading-underscore, allow-pascal-case
- `interface-name`: never-prefix (no `I` prefix)
- `no-console`: off (console usage allowed)
- `object-literal-sort-keys`: off
- `trailing-comma`: off
- `ordered-imports`: off
- `max-line-length`: off

## Key Dependencies

- `@xmldom/xmldom` — DOM parser for XML
- `xml-crypto` — XML signature and verification
- `@authenio/xml-encryption` — XML encryption/decryption
- `node-forge` — Crypto operations (certs, keys)
- `node-rsa` — RSA key operations
- `pako` — Deflate/inflate for redirect binding
- `xpath` — XPath queries on XML documents
