"""Bounded reader for the documented CGP textual object format.

Reference: https://doc.communigatepro.ru/development/Data.html
XML and application-specific objects are deliberately unsupported. Empty
DataBlocks are preserved as observations; this does not define unset semantics.
Decimal escapes are limited to nonzero ASCII bytes; non-ASCII bytes have
ambiguous UTF-8 assembly semantics and require an explicit Unicode escape.
"""
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import re
import unicodedata

from .core import Error


MAX_INPUT = 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 10000
WHITESPACE = " \t\r\n"
UNICODE_ESCAPE = re.compile(r"'([0-9a-fA-F]{1,6})'")


class ParseError(Error):
    """A safe error that never contains server response data."""


@dataclass(frozen=True)
class Value:
    kind: str
    value: object


def _invalid():
    raise ParseError("Invalid or unsupported CGP data")


def _atom_character(character):
    return character.isascii() and (character.isalnum() or character in ".-_@") or ord(character) >= 128


class _Parser:
    def __init__(self, text):
        if not isinstance(text, str) or len(text) > MAX_INPUT:
            raise ParseError("CGP input size or type limit")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeError:
            raise ParseError("Invalid CGP text encoding") from None
        if size > MAX_INPUT:
            raise ParseError("CGP input size or type limit")
        if any((unicodedata.category(c) in ("Cc", "Cf", "Cs") and c not in "\t\r\n") for c in text):
            raise ParseError("Invalid CGP text control character")
        self.text = text
        self.index = 0
        self.nodes = 0

    def node(self):
        # Count parsed objects and string fragments, including dictionary keys.
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise ParseError("CGP object count limit")

    def space(self):
        while self.index < len(self.text):
            if self.text[self.index] in WHITESPACE:
                self.index += 1
            elif self.text.startswith("//", self.index):
                self.index += 2
                while self.index < len(self.text) and self.text[self.index] not in "\r\n":
                    self.index += 1
            elif self.text.startswith("/*", self.index):
                end = self.text.find("*/", self.index + 2)
                if end < 0:
                    _invalid()
                self.index = end + 2
            else:
                break

    def take(self, character):
        self.space()
        if self.index >= len(self.text) or self.text[self.index] != character:
            _invalid()
        self.index += 1

    def string_start(self):
        return self.index < len(self.text) and (self.text[self.index] == '"' or _atom_character(self.text[self.index]))

    def quoted(self):
        self.index += 1
        characters = []
        while self.index < len(self.text):
            character = self.text[self.index]
            self.index += 1
            if character == '"':
                return "".join(characters)
            if character in "\t\r\n":
                _invalid()
            if character == "\\":
                if self.index >= len(self.text):
                    _invalid()
                escape = self.text[self.index]
                self.index += 1
                simple = {'"': '"', "\\": "\\", "r": "\r", "n": "\n", "e": "\n", "t": "\t"}
                if escape in simple:
                    character = simple[escape]
                elif escape in "0123456789":
                    digits = escape + self.text[self.index:self.index + 2]
                    if not re.fullmatch(r"[0-9]{3}", digits):
                        _invalid()
                    self.index += 2
                    number = int(digits)
                    if not 1 <= number <= 127:
                        _invalid()
                    character = chr(number)
                elif escape == "u":
                    match = UNICODE_ESCAPE.match(self.text, self.index)
                    if match is None:
                        _invalid()
                    self.index = match.end()
                    number = int(match[1], 16)
                    if not 1 <= number <= 0x10FFFF or 0xD800 <= number <= 0xDFFF:
                        _invalid()
                    character = chr(number)
                else:
                    _invalid()
            characters.append(character)
        _invalid()

    def string(self):
        self.space()
        if not self.string_start():
            _invalid()
        pieces = []
        while self.string_start():
            self.node()
            if self.text[self.index] == '"':
                pieces.append(self.quoted())
            else:
                start = self.index
                while self.index < len(self.text) and _atom_character(self.text[self.index]):
                    self.index += 1
                pieces.append(self.text[start:self.index])
            self.space()
        return "".join(pieces)

    def dictionary(self, depth):
        self.take("{")
        values = {}
        self.space()
        while self.index < len(self.text) and self.text[self.index] != "}":
            key = self.string()
            if key in values:
                raise ParseError("Duplicate CGP dictionary key")
            self.take("=")
            values[key] = self.object(depth + 1)
            self.take(";")
            self.space()
        self.take("}")
        return Value("dictionary", values)

    def array(self, depth):
        self.take("(")
        values = []
        self.space()
        if self.index < len(self.text) and self.text[self.index] == ")":
            self.index += 1
            return Value("array", ())
        while True:
            values.append(self.object(depth + 1))
            self.space()
            if self.index < len(self.text) and self.text[self.index] == ")":
                self.index += 1
                return Value("array", tuple(values))
            self.take(",")

    def datablock(self):
        self.index += 1
        end = self.text.find("]", self.index)
        if end < 0:
            _invalid()
        raw = self.text[self.index:end]
        if not re.fullmatch(r"[A-Za-z0-9+/= \t\r\n]*", raw):
            _invalid()
        self.index = end + 1
        return Value("datablock", re.sub(r"[ \t\r\n]", "", raw))

    def typed(self):
        start = self.index
        while self.index < len(self.text) and self.text[self.index] not in WHITESPACE + "{}();,=":
            if self.text.startswith(("//", "/*"), self.index):
                break
            self.index += 1
        word = self.text[start:self.index]
        if word == "#NULL#":
            return Value("null", None)
        if word in ("#TPAST", "#TFUTURE"):
            return Value("timestamp", word[2:])
        if word.startswith("#T"):
            timestamp = word[2:]
            if not re.fullmatch(r"[0-9]{2}-[0-9]{2}-[0-9]{4}(?:_[0-9]{2}:[0-9]{2}:[0-9]{2})?", timestamp):
                _invalid()
            try:
                parsed = datetime.strptime(timestamp, "%d-%m-%Y_%H:%M:%S" if "_" in timestamp else "%d-%m-%Y")
            except ValueError:
                raise ParseError("Invalid CGP timestamp") from None
            if not 1970 <= parsed.year <= 2038:
                _invalid()
            return Value("timestamp", timestamp)
        if word.startswith("#I"):
            match = re.fullmatch(r"#I\[([0-9a-fA-F:.]+)\](?::([0-9]+))?", word)
            if match is None:
                _invalid()
            try:
                address = str(ipaddress.ip_address(match[1]))
                port = int(match[2]) if match[2] is not None else None
            except ValueError:
                raise ParseError("Invalid CGP address") from None
            if port is not None and not 0 <= port <= 65535:
                _invalid()
            return Value("ip", (address, port))
        match = re.fullmatch(r"#(-?)(?:(0x)([0-9a-fA-F]+)|(0o)([0-7]+)|(0b)([01]+)|([0-9]+))", word)
        if match is None:
            _invalid()
        base, digits = (16, match[3]) if match[2] else (8, match[5]) if match[4] else (2, match[7]) if match[6] else (10, match[8])
        digits = digits.lstrip("0") or "0"
        if len(digits) > 64:
            _invalid()
        number = int(digits, base) * (-1 if match[1] else 1)
        if not -(2 ** 63) <= number < 2 ** 63:
            _invalid()
        return Value("number", number)

    def object(self, depth=0):
        if depth > MAX_DEPTH:
            raise ParseError("CGP nesting depth limit")
        self.node()
        self.space()
        if self.index >= len(self.text):
            _invalid()
        character = self.text[self.index]
        if character == "{":
            return self.dictionary(depth)
        if character == "(":
            return self.array(depth)
        if character == "[":
            return self.datablock()
        if character == "#":
            return self.typed()
        return Value("string", self.string())


def parse(text):
    """Read one complete supported object; never return a partial value."""
    parser = _Parser(text)
    value = parser.object()
    parser.space()
    if parser.index != len(text):
        _invalid()
    return value


def parse_dictionary(text):
    """Read one complete dictionary; never return a partial projection."""
    value = parse(text)
    if value.kind != "dictionary":
        _invalid()
    return value.value
