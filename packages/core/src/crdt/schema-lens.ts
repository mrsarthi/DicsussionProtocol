/**
 * @dicsussion/crdt — Schema Lenses
 *
 * Bidirectional declarative JSON schema transformations for
 * cross-version compatibility per RFC 002 §5.
 *
 * Supports add_field, rename_field, remove_field operations.
 * Upcast (v1→v2): populates missing fields with defaults.
 * Downcast (v2→v1): strips unknown fields safely.
 */

import type { LensOperation, SchemaLens } from './types.js';

/** Registry of available schema lenses. */
const lensRegistry = new Map<string, SchemaLens>();

/**
 * Register a schema lens for later lookup.
 */
export function registerLens(lens: SchemaLens): void {
  lensRegistry.set(lens.lensId, lens);
}

/**
 * Find a lens by its ID.
 */
export function getLens(lensId: string): SchemaLens | undefined {
  return lensRegistry.get(lensId);
}

/**
 * Find a lens path between two schema versions.
 *
 * @param fromSchema Source schema identifier.
 * @param toSchema Target schema identifier.
 * @returns The matching lens or undefined.
 */
export function findLensPath(
  fromSchema: string,
  toSchema: string,
): SchemaLens | undefined {
  for (const lens of lensRegistry.values()) {
    if (lens.fromSchema === fromSchema && lens.toSchema === toSchema) {
      return lens;
    }
  }
  return undefined;
}

/**
 * Apply a schema lens to transform data between versions.
 *
 * @param data The data object to transform.
 * @param lens The lens defining the transformation.
 * @param direction 'upcast' (old→new) or 'downcast' (new→old).
 * @returns Transformed data (deep-cloned, original untouched).
 */
export function applyLens(
  data: Record<string, unknown>,
  lens: SchemaLens,
  direction: 'upcast' | 'downcast',
): Record<string, unknown> {
  // Deep clone to avoid mutating original
  const result = structuredClone(data);

  const operations =
    direction === 'upcast'
      ? lens.operations
      : [...lens.operations].reverse();

  for (const op of operations) {
    if (direction === 'upcast') {
      applyUpcastOp(result, op);
    } else {
      applyDowncastOp(result, op);
    }
  }

  return result;
}

/**
 * Apply a single upcast operation (v1 → v2).
 * add_field: populate missing fields with defaults.
 * rename_field: rename from old name to new name.
 * remove_field: no-op on upcast (field already absent in source).
 */
function applyUpcastOp(data: Record<string, unknown>, op: LensOperation): void {
  switch (op.op) {
    case 'add_field': {
      setNestedDefault(data, op.path, op.default);
      break;
    }
    case 'rename_field': {
      renameNestedField(data, op.from, op.to);
      break;
    }
    case 'remove_field': {
      // Upcast: no-op — field shouldn't exist in older schema
      break;
    }
  }
}

/**
 * Apply a single downcast operation (v2 → v1).
 * add_field becomes remove_field (strip unknown fields).
 * rename_field becomes reverse rename.
 * remove_field becomes add_field with default.
 */
function applyDowncastOp(data: Record<string, unknown>, op: LensOperation): void {
  switch (op.op) {
    case 'add_field': {
      // Downcast: strip the field that was added in newer version
      deleteNestedField(data, op.path);
      break;
    }
    case 'rename_field': {
      // Downcast: reverse the rename
      renameNestedField(data, op.to, op.from);
      break;
    }
    case 'remove_field': {
      // Downcast: no-op — field was removed in newer version
      break;
    }
  }
}

/**
 * Set a default value at a nested path if it doesn't exist.
 * Supports wildcard paths like "/messages/*\/reactions".
 */
function setNestedDefault(
  obj: Record<string, unknown>,
  path: string,
  defaultValue: unknown,
): void {
  const segments = parsePath(path);
  setAtPath(obj, segments, 0, defaultValue);
}

/**
 * Rename a nested field from one path to another.
 */
function renameNestedField(
  obj: Record<string, unknown>,
  fromPath: string,
  toPath: string,
): void {
  const fromSegments = parsePath(fromPath);
  const toSegments = parsePath(toPath);

  const value = getAtPath(obj, fromSegments, 0);
  if (value !== undefined) {
    deleteAtPath(obj, fromSegments, 0);
    setAtPath(obj, toSegments, 0, value, true);
  }
}

/**
 * Delete a nested field.
 */
function deleteNestedField(
  obj: Record<string, unknown>,
  path: string,
): void {
  const segments = parsePath(path);
  deleteAtPath(obj, segments, 0);
}

/** Parse a JSON path string into segments. */
function parsePath(path: string): string[] {
  return path.split('/').filter((s) => s.length > 0);
}

/** Recursively set a value at a path, supporting wildcards. */
function setAtPath(
  obj: Record<string, unknown>,
  segments: string[],
  index: number,
  value: unknown,
  overwrite: boolean = false,
): void {
  if (index >= segments.length) return;

  const segment = segments[index]!;

  if (index === segments.length - 1) {
    // Terminal segment
    if (segment === '*') {
      // Apply to all children
      for (const key of Object.keys(obj)) {
        const child = obj[key] as Record<string, unknown>;
        if (typeof child === 'object' && child !== null) {
          // For wildcard terminal, this doesn't make sense — skip
        }
      }
    } else if (overwrite || !(segment in obj)) {
      obj[segment] = structuredClone(value);
    }
    return;
  }

  if (segment === '*') {
    // Wildcard: apply to all child objects
    for (const key of Object.keys(obj)) {
      const child = obj[key];
      if (typeof child === 'object' && child !== null) {
        setAtPath(child as Record<string, unknown>, segments, index + 1, value, overwrite);
      }
    }
  } else {
    const child = obj[segment];
    if (typeof child === 'object' && child !== null) {
      setAtPath(child as Record<string, unknown>, segments, index + 1, value, overwrite);
    }
  }
}

/** Recursively get a value at a path. */
function getAtPath(
  obj: Record<string, unknown>,
  segments: string[],
  index: number,
): unknown {
  if (index >= segments.length) return obj;

  const segment = segments[index]!;
  const child = obj[segment];

  if (index === segments.length - 1) {
    return child;
  }

  if (typeof child === 'object' && child !== null) {
    return getAtPath(child as Record<string, unknown>, segments, index + 1);
  }

  return undefined;
}

/** Recursively delete a value at a path. */
function deleteAtPath(
  obj: Record<string, unknown>,
  segments: string[],
  index: number,
): void {
  if (index >= segments.length) return;

  const segment = segments[index]!;

  if (index === segments.length - 1) {
    if (segment === '*') {
      for (const key of Object.keys(obj)) {
        delete obj[key];
      }
    } else {
      delete obj[segment];
    }
    return;
  }

  if (segment === '*') {
    for (const key of Object.keys(obj)) {
      const child = obj[key];
      if (typeof child === 'object' && child !== null) {
        deleteAtPath(child as Record<string, unknown>, segments, index + 1);
      }
    }
  } else {
    const child = obj[segment];
    if (typeof child === 'object' && child !== null) {
      deleteAtPath(child as Record<string, unknown>, segments, index + 1);
    }
  }
}

/**
 * Clear the lens registry. Useful for testing.
 */
export function clearLensRegistry(): void {
  lensRegistry.clear();
}
