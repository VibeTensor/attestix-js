/**
 * Canonical JSON serialization matching the Python Attestix engine's
 * `auth.crypto.canonicalize_json`.
 *
 * This is NOT strict RFC 8785 — it is byte-for-byte compatible with what the
 * Python engine actually produces:
 *   json.dumps(normalize(obj), sort_keys=True, separators=(",",":"),
 *              ensure_ascii=False).encode("utf-8")
 *
 * Rules (see SPEC.md §3):
 *  - object keys sorted by Unicode code point (Python default string sort)
 *  - compact separators: "," and ":"
 *  - non-ASCII emitted as raw UTF-8 (NOT \uXXXX escapes)
 *  - every string NFC-normalized
 *  - whole-valued floats coerced to integers (1.0 -> 1)
 *  - control chars U+0000–U+001F escaped as \b \t \n \f \r or \u00xx (lowercase)
 *  - "/", "<", ">", "&" NOT escaped; U+007F emitted raw
 *
 * Numbers that would serialize differently in JS vs Python (exponential
 * notation, signed zero, NaN/Infinity) are rejected up front with
 * {@link JcsUnsupportedValueError} so a verifier never produces silently-wrong
 * canonical bytes. These never occur in real Attestix payloads.
 */

/** Thrown when a value cannot be canonicalized to match the Python engine. */
export class JcsUnsupportedValueError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'JcsUnsupportedValueError';
	}
}

export type JsonValue =
	| string
	| number
	| bigint
	| boolean
	| null
	| JsonValue[]
	| { [key: string]: JsonValue };

/**
 * Parse JSON while preserving integers beyond Number.MAX_SAFE_INTEGER (2^53-1)
 * as BigInt, so they survive {@link canonicalize} without precision loss. A
 * plain `JSON.parse` rounds such integers to the nearest double before the
 * canonicalizer ever sees them, which would diverge from the Python/Go/Rust
 * ports. Use this to parse any payload that may carry large integer fields.
 *
 * Requires reviver source access (Node >= 21 / modern engines). Where that is
 * unavailable it degrades to plain JSON.parse behaviour for oversized integers.
 */
export function parseCanonicalJson(text: string): JsonValue {
	return JSON.parse(
		text,
		function (
			_key: string,
			value: unknown,
			context?: { source?: string },
		): unknown {
			if (
				typeof value === 'number' &&
				Number.isInteger(value) &&
				!Number.isSafeInteger(value) &&
				context &&
				typeof context.source === 'string' &&
				/^-?\d+$/.test(context.source)
			) {
				return BigInt(context.source);
			}
			return value;
		},
	) as JsonValue;
}

/**
 * Serialize a JSON value to its canonical string form (matching Python).
 * Use {@link canonicalize} to get the UTF-8 bytes for signing/verification.
 */
export function canonicalizeToString(value: JsonValue): string {
	return serialize(value);
}

/**
 * Produce canonical UTF-8 bytes for a JSON value, byte-identical to the Python
 * engine's `canonicalize_json`.
 */
export function canonicalize(value: JsonValue): Uint8Array {
	return new TextEncoder().encode(serialize(value));
}

function serialize(value: JsonValue): string {
	if (value === null) {
		return 'null';
	}
	const t = typeof value;
	if (t === 'boolean') {
		return value ? 'true' : 'false';
	}
	if (t === 'string') {
		return serializeString(value as string);
	}
	if (t === 'number') {
		return serializeNumber(value as number);
	}
	if (t === 'bigint') {
		// A BigInt is always an exact integer; emit its decimal string. This is
		// how integers beyond 2^53 (which a JS `number` cannot represent) are
		// canonicalized to match the Python/Go/Rust ports byte-for-byte.
		return (value as bigint).toString();
	}
	if (Array.isArray(value)) {
		return '[' + value.map((v) => serialize(v)).join(',') + ']';
	}
	if (t === 'object') {
		const obj = value as { [key: string]: JsonValue };
		// Sort keys by Unicode code point (matches Python's default str sort).
		const keys = Object.keys(obj).sort(compareByCodePoint);
		const parts: string[] = [];
		for (const k of keys) {
			parts.push(serializeString(k) + ':' + serialize(obj[k]));
		}
		return '{' + parts.join(',') + '}';
	}
	throw new JcsUnsupportedValueError(
		`Cannot canonicalize value of type ${t}`,
	);
}

/**
 * Compare two strings by Unicode code point. JS string comparison and Array
 * sort compare by UTF-16 code unit, which diverges from Python's code-point
 * sort for astral characters (> U+FFFF). Attestix keys are all BMP, but we
 * match Python exactly regardless.
 */
function compareByCodePoint(a: string, b: string): number {
	const ai = a[Symbol.iterator]();
	const bi = b[Symbol.iterator]();
	for (;;) {
		const an = ai.next();
		const bn = bi.next();
		if (an.done && bn.done) return 0;
		if (an.done) return -1;
		if (bn.done) return 1;
		const ac = an.value.codePointAt(0) as number;
		const bc = bn.value.codePointAt(0) as number;
		if (ac !== bc) return ac - bc;
	}
}

function serializeNumber(n: number): string {
	if (!Number.isFinite(n)) {
		throw new JcsUnsupportedValueError(
			`Non-finite number (${n}) cannot be canonicalized`,
		);
	}
	// Reject signed zero: Python emits "-0.0", JS would emit "0".
	if (n === 0 && 1 / n === -Infinity) {
		throw new JcsUnsupportedValueError(
			'Signed zero (-0) cannot be canonicalized (Python emits -0.0)',
		);
	}
	if (Number.isInteger(n)) {
		// Python serializes ints and whole-valued floats without a decimal
		// point or exponent. JS String(int) does too for safe integers; guard
		// against magnitudes that JS would render in exponential form.
		const s = String(n);
		if (s.includes('e') || s.includes('E')) {
			throw new JcsUnsupportedValueError(
				`Integer ${n} would serialize in exponential notation; ` +
					'use a string field instead',
			);
		}
		return s;
	}
	// Non-integer finite float: allowed only if JS renders it without an
	// exponent (Python's json.dumps would otherwise diverge, e.g. 1e-7).
	const s = String(n);
	if (s.includes('e') || s.includes('E')) {
		throw new JcsUnsupportedValueError(
			`Float ${n} requires exponential notation; not supported for ` +
				'cross-engine canonicalization',
		);
	}
	return s;
}

const ESCAPE_MAP: Record<number, string> = {
	0x08: '\\b',
	0x09: '\\t',
	0x0a: '\\n',
	0x0c: '\\f',
	0x0d: '\\r',
	0x22: '\\"',
	0x5c: '\\\\',
};

function serializeString(raw: string): string {
	// NFC-normalize first (matches unicodedata.normalize("NFC", s)).
	const s = raw.normalize('NFC');
	let out = '"';
	for (const ch of s) {
		const code = ch.codePointAt(0) as number;
		const mapped = ESCAPE_MAP[code];
		if (mapped !== undefined) {
			out += mapped;
		} else if (code < 0x20) {
			// Other control chars: \u00xx with lowercase hex (matches json.dumps).
			out += '\\u' + code.toString(16).padStart(4, '0');
		} else {
			// Everything else (incl. non-ASCII and U+007F) emitted raw; the
			// final UTF-8 encoding matches Python's ensure_ascii=False output.
			out += ch;
		}
	}
	out += '"';
	return out;
}
