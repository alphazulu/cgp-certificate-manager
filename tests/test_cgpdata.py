"""Documented CGP grammar and adversarial parsing boundaries."""
from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from cgp_cert_manager import cgpdata as c


class CGPDataTests(unittest.TestCase):
    def parse(self, text):
        return c.parse_dictionary(text)

    def value(self, text):
        return self.parse("{item=" + text + ";}")["item"]

    def test_empty_and_nested_structures_preserve_types(self):
        self.assertEqual(self.parse("{}"), {})
        data = self.parse('{first=(); nested={flag=YES; chain=[];}; values=(word, [YQ==], #17, #NULL#);}')
        self.assertEqual(data["first"], c.Value("array", ()))
        self.assertEqual(data["nested"].kind, "dictionary")
        self.assertEqual(data["nested"].value["chain"], c.Value("datablock", ""))
        self.assertEqual(data["values"], c.Value("array", (c.Value("string", "word"), c.Value("datablock", "YQ=="), c.Value("number", 17), c.Value("null", None))))
        with self.assertRaises(FrozenInstanceError):
            data["first"].kind = "string"

    def test_generic_parse_requires_complete_typed_objects(self):
        self.assertEqual(c.parse('(example.com,"mail.example.com")'), c.Value("array", (c.Value("string", "example.com"), c.Value("string", "mail.example.com"))))
        self.assertEqual(c.parse("#NULL#"), c.Value("null", None))
        self.assertEqual(c.parse("YES"), c.Value("string", "YES"))
        for text in ('("example.com)', '(example.com) trailing', '(example.com,)', '(example.com)(other.com)'):
            with self.subTest(text=text), self.assertRaises(c.ParseError):
                c.parse(text)

    def test_case_sensitive_and_quoted_keys(self):
        data = self.parse('{Key=first; key=second; "Third Key"=third; ""=empty;}')
        self.assertEqual(set(data), {"Key", "key", "Third Key", ""})
        self.assertEqual(data["Key"].value, "first")
        self.assertEqual(data["key"].value, "second")

    def test_atoms_and_concatenated_strings(self):
        data = self.parse('{atom=user.name-01_x@example.test; русское=значение; joined="one" /* break */ "two" tail; "Ke"y=YES;}')
        self.assertEqual(data["atom"].value, "user.name-01_x@example.test")
        self.assertEqual(data["русское"].value, "значение")
        self.assertEqual(data["joined"].value, "onetwotail")
        self.assertEqual(data["Key"], c.Value("string", "YES"))
        self.assertEqual(self.value('"/var/lib/example"'), c.Value("string", "/var/lib/example"))
        self.assertEqual(self.value("123"), c.Value("string", "123"))

    def test_documented_string_escapes(self):
        value = self.value(r'''"quote\" slash\\ CR\r LF\n EOL\e TAB\t ascii\065 unicode\u'2764'"''')
        self.assertEqual(value.value, 'quote" slash\\ CR\r LF\n EOL\n TAB\t asciiA unicode❤')
        self.assertEqual(self.value(r'"\012"').value, "\x0c")
        self.assertEqual(self.value(r'''"\u'ff'"''').value, "ÿ")
        self.assertEqual(self.value(r'''"\u'1f600'"''').value, "😀")
        self.assertEqual(self.value('""'), c.Value("string", ""))

    def test_comments_and_multiline_whitespace(self):
        text = ' // prefix\r\n { /* header */ a=one; // line\n b=( /* first */ #2, #3 /* final */ ); } // tail'
        self.assertEqual(self.parse(text)["b"].value, (c.Value("number", 2), c.Value("number", 3)))
        self.assertEqual(self.parse('/**/ {a=#1/* comment */;}\t\r\n'), {"a": c.Value("number", 1)})
        self.assertEqual(self.value('"// is literal /* text */"').value, "// is literal /* text */")

    def test_datablock_normalization_preserves_empty_and_padding(self):
        self.assertEqual(self.value("[ Y Q = = \t\r\n]"), c.Value("datablock", "YQ=="))
        self.assertEqual(self.value("[]"), c.Value("datablock", ""))
        self.assertEqual(self.value("[//==]"), c.Value("datablock", "//=="))
        # Semantic/canonical Base64 validation belongs to the field projection.
        self.assertEqual(self.value("[A===]"), c.Value("datablock", "A==="))
        self.assertEqual(self.value("[A]"), c.Value("datablock", "A"))

    def test_integer_bases_bounds_and_zero(self):
        values = {"#-234657": -234657, "#0x17EF": 6127, "#-0b1000111000": -568,
                  "#0o17": 15, "#0000": 0, "#-0": 0, "#0000007": 7,
                  "#9223372036854775807": 2 ** 63 - 1,
                  "#-9223372036854775808": -(2 ** 63)}
        for text, number in values.items():
            with self.subTest(text=text):
                self.assertEqual(self.value(text), c.Value("number", number))

    def test_timestamps_and_special_endpoints(self):
        for text in ("22-10-2009_15:24:45", "01-01-1970", "31-12-2038", "PAST", "FUTURE"):
            with self.subTest(text=text):
                self.assertEqual(self.value("#T" + text), c.Value("timestamp", text))

    def test_ipv4_ipv6_and_ports(self):
        self.assertEqual(self.value("#I[10.0.44.55]:25"), c.Value("ip", ("10.0.44.55", 25)))
        self.assertEqual(self.value("#I[2001:0DB8::1]"), c.Value("ip", ("2001:db8::1", None)))
        self.assertEqual(self.value("#I[::1]:0"), c.Value("ip", ("::1", 0)))
        self.assertEqual(self.value("#I[127.0.0.1]:65535"), c.Value("ip", ("127.0.0.1", 65535)))

    def test_top_level_dictionary_and_entire_document_required(self):
        for text in ("", " \n // only comment", "()", "YES", "[YQ==]", "#1", "{} trailing", "{}{}", "{};", "250 {a=YES;}"):
            with self.subTest(text=text), self.assertRaises(c.ParseError):
                self.parse(text)

    def test_duplicate_keys_at_all_depths_and_after_decoding(self):
        for text in ('{a=1;a=2;}', '{root={a=1;a=2;};}', '{root=({a=1;a=2;});}',
                     r'{"Private\083ecureKey"=one; PrivateSecureKey=two;}', '{"a"b=one; ab=two;}'):
            with self.subTest(text=text), self.assertRaisesRegex(c.ParseError, "Duplicate"):
                self.parse(text)

    def test_nested_and_quoted_keys_are_not_top_level_fields(self):
        data = self.parse('{nested={PrivateSecureKey=[YQ==];}; text="SecureCertificate=[Yg==];"; CAChain=[];}')
        self.assertNotIn("PrivateSecureKey", data)
        self.assertNotIn("SecureCertificate", data)
        self.assertEqual(data["CAChain"].value, "")

    def test_structural_errors_and_truncation_fail_closed(self):
        for text in ('{', '{a', '{a=', '{a=YES', '{a=YES}', '{a=YES;;}', '{a==YES;}', '{=YES;}',
                     '{a=(one,);}', '{a=(,one);}', '{a=(one', '{a=(', '{a=(one two;}',
                     '{a=[abc;}', '{a=[a?];}', '{a=[a/*x*/];}', '{a=YES;/* unfinished',
                     '{a="unfinished;}', '{a="unfinished\\', '{a="line\nline";}',
                     '{a=/unquoted/path;}', '{a=a+b;}', '{a=<xml/>;}', '{a=#(custom:1234);}'):
            with self.subTest(text=text), self.assertRaises(c.ParseError):
                self.parse(text)

    def test_invalid_escapes_never_reveal_input(self):
        cases = [r'"\q"', r'"\12"', r'"\1x3"', r'"\000"', r'"\128"', r'"\195\169"', r'"\255"', r'"\999"',
                 r'''"\u'0'"''', r'''"\u'd800'"''', r'''"\u'dfff'"''', r'''"\u'110000'"''',
                 r'''"\u'1000000'"''', r'''"\u'nothex'"''', r'"\u1234"']
        for text in cases:
            with self.subTest(text=text), self.assertRaises(c.ParseError) as caught:
                self.parse('{SECRET_KEY=' + text + ';}')
            self.assertNotIn("SECRET_KEY", str(caught.exception))
            self.assertNotIn(text, str(caught.exception))

    def test_invalid_atomic_types(self):
        invalid = ("#", "#1foo", "#NULL", "#NULL#oops", "#0x", "#0xG", "#0o8", "#0b2", "#+1",
                   "#9223372036854775808", "#-9223372036854775809", "#" + "1" * 65,
                   "#Tbad", "#T29-02-2009", "#T01-01-1969", "#T01-01-2039", "#T01-01-2000_24:00:00",
                   "#I[999.0.0.1]", "#I[]", "#I[::1]:65536", "#I[::1]:-1", "#I[fe80::1%eth0]")
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(c.ParseError):
                self.value(text)

    def test_huge_port_conversion_has_a_safe_error(self):
        with self.assertRaises(c.ParseError) as caught:
            self.value("#I[127.0.0.1]:" + "9" * 5000)
        self.assertNotIn("99999", str(caught.exception))

    def test_raw_controls_and_invalid_unicode_rejected_everywhere(self):
        for bad in ("\x00", "\x01", "\x0b", "\x1b", "\x7f", "\x85", "\u202e", "\ud800"):
            for text in ('{a="' + bad + '";}', '/*' + bad + '*/ {}'):
                with self.subTest(bad=repr(bad)), self.assertRaises(c.ParseError):
                    self.parse(text)

    def test_resource_limits_include_utf8_bytes_depth_and_fragments(self):
        for text in (None, b"{}", " " * (c.MAX_INPUT + 1), "é" * (c.MAX_INPUT // 2 + 1)):
            with self.subTest(kind=type(text).__name__), self.assertRaises(c.ParseError):
                self.parse(text)
        with patch.object(c, "MAX_DEPTH", 2):
            self.assertEqual(self.parse('{a={b={};};}')["a"].kind, "dictionary")
            with self.assertRaisesRegex(c.ParseError, "depth"):
                self.parse('{a={b={c=deep;};};}')
        with patch.object(c, "MAX_NODES", 4):
            self.assertEqual(self.value('"one"').value, "one")
            with self.assertRaisesRegex(c.ParseError, "count"):
                self.value('"one" "two"')
        with self.assertRaisesRegex(c.ParseError, "count"):
            self.value("(" + ",".join("#1" for _ in range(c.MAX_NODES)) + ")")

    def test_large_supported_document_and_repeated_unicode_escapes(self):
        text = '{data="' + r"\u'0061'" * 10000 + '";}'
        self.assertEqual(len(self.parse(text)["data"].value), 10000)
        payload = "YQ==" + " " * (c.MAX_INPUT - len("{a=[];}") - 4)
        self.assertEqual(self.parse("{a=[" + payload + "];}")["a"].value, "YQ==")

    def test_truncations_never_return_partial_settings(self):
        text = '{PrivateSecureKey=[YQ==]; SecureCertificate=[Yg==]; CAChain=[]; CertificateType=YES;}'
        for index in range(len(text)):
            with self.subTest(index=index), self.assertRaises(c.ParseError):
                self.parse(text[:index])
