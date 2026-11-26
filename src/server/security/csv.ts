const FORMULA_PREFIX = /^[=+\-@\t\r]/

/**
 * Escapes CSV values to prevent Excel / Sheets formula injection (DDE/CSV injection)
 * and conforms to RFC 4180 quoting rules.
 */
export function sanitizeCsvCell(value: unknown): string {
  if (value === null || value === undefined) return ''
  let str = String(value)
  if (FORMULA_PREFIX.test(str)) {
    str = `'${str}`
  }
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

export function buildCsvDocument(
  headers: string[],
  rows: Array<Array<unknown>>,
): string {
  return [
    headers.map(sanitizeCsvCell).join(','),
    ...rows.map((row) => row.map(sanitizeCsvCell).join(',')),
  ].join('\n')
}
