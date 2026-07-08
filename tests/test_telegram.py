import unittest
from unittest import mock

from autosoc.telegram.client import TelegramBotClient, escape_markdown
from autosoc.telegram.listener import extract_command, extract_contact


class MarkdownEscapeTests(unittest.TestCase):
    def test_escapes_special_characters(self):
        self.assertEqual(escape_markdown("a_b*c`d[e"), r"a\_b\*c\`d\[e")

    def test_plain_text_unchanged(self):
        self.assertEqual(escape_markdown("192.168.1.1:445"), "192.168.1.1:445")


class TokenRedactionTests(unittest.TestCase):
    def test_error_messages_do_not_leak_token(self):
        token = "123456:SECRET-TOKEN-VALUE"
        client = TelegramBotClient(token)

        with mock.patch(
            "autosoc.telegram.client.requests.get",
            side_effect=Exception(f"connection to https://api.telegram.org/bot{token}/getMe failed"),
        ):
            ok, data = client.get_me()

        self.assertFalse(ok)
        self.assertNotIn(token, data["description"])
        self.assertIn("***TOKEN***", data["description"])

    def test_disabled_client_reports_missing_token(self):
        client = TelegramBotClient("")
        ok, data = client.send_message("1", "hi")
        self.assertFalse(ok)
        self.assertIn("token is empty", data["description"])


class UpdateParsingTests(unittest.TestCase):
    def test_extract_command_variants(self):
        self.assertEqual(extract_command("/start"), "start")
        self.assertEqual(extract_command("/start@AutoSOC_Bot now"), "start")
        self.assertEqual(extract_command("/HELP"), "help")
        self.assertEqual(extract_command("hello"), "")

    def test_extract_contact(self):
        update = {
            "message": {
                "text": " /start ",
                "chat": {"id": 42},
                "from": {"id": 7, "username": "alice"},
            }
        }
        chat_id, user_id, text, from_user = extract_contact(update)
        self.assertEqual(chat_id, 42)
        self.assertEqual(user_id, 7)
        self.assertEqual(text, "/start")
        self.assertEqual(from_user["username"], "alice")

    def test_extract_contact_ignores_non_messages(self):
        self.assertIsNone(extract_contact({"channel_post": {}}))


if __name__ == "__main__":
    unittest.main()
