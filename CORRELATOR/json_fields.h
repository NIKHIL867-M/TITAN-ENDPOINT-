// json_fields.h
//
// Lightweight, dependency-free extraction of individual top-level fields
// from a flat, single-line JSON object -- exactly the shape every one of
// TITAN's 5 endpoints already emits (hand-rolled via ostringstream, never a
// full JSON library). No general JSON parser is needed: the Correlator only
// ever needs a handful of well-known top-level keys (t_unix_ms, pid,
// parent_pid, endpoint, type), and every endpoint's schema puts those at
// the top level even when other nested objects exist elsewhere in the
// record (e.g. Port's "device":{...}).
#pragma once

#include <cstdint>
#include <string>

namespace correlator {

// Extracts a numeric value for "key":<number> (bare, unquoted). Returns
// false if the key isn't present or isn't followed by a parseable integer.
bool ExtractJsonNumber(const std::string& line, const std::string& key, int64_t& out);

// Extracts a string value for "key":"<value>" (quoted). The scan for the
// closing quote IS escape-aware (a "\\\"" inside the value never terminates
// it early -- found live: a Windows command_line beginning with a quoted
// path is JSON-encoded starting with \", which a naive scan mistook for the
// end), but the returned substring itself is NOT un-escaped (still a raw
// copy of the JSON bytes, \\ stays \\ and \" stays \") -- fine for every
// current caller (identifiers, paths, command lines used for display/
// re-embedding), just not a general-purpose JSON string decoder.
bool ExtractJsonString(const std::string& line, const std::string& key, std::string& out);

// Extracts a bare JSON boolean value for "key":true / "key":false. Returns
// false (and leaves out untouched) if the key isn't present or isn't
// followed by exactly one of those two literals.
bool ExtractJsonBool(const std::string& line, const std::string& key, bool& out);

} // namespace correlator
