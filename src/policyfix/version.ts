// Versions hashed into policy_sha and checked by the runner. Bump ENGINE_VERSION whenever guard/normaliser
// behaviour changes; bump GRAMMAR_VERSION whenever the supported shell/SQL/git grammar subset changes.

/** Version of the policyfix evaluation engine (guard + normaliser + scorer). */
export const ENGINE_VERSION = '0.1.0';

/** Version of the supported command grammar (docs/GRAMMAR.md); matches CONTRACTS C3 contexts (`"1"`). */
export const GRAMMAR_VERSION = '1';
