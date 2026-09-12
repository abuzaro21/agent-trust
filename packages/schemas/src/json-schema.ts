/**
 * Minimal typing for the JSON Schema objects defined in ./schemas.
 * Schemas are authored as TypeScript modules so the whole toolchain
 * (tsc NodeNext, vitest) consumes them without import-attribute friction;
 * a JSON emitter can be added for external publication later.
 */
export interface JsonSchema {
  $schema?: string;
  $id: string;
  title?: string;
  description?: string;
  [keyword: string]: unknown;
}
