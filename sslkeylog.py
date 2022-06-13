#!/usr/bin/env python3
import os

from frida_tools.application import ConsoleApplication

from pyasn1.codec.der import decoder

AGENT_FILENAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.js")


class Application(ConsoleApplication):
    SESSION_ID_LENGTH = 32
    CLIENT_RANDOM_LENGTH = 32
    MASTER_KEY_LENGTH = 48

    def _add_options(self, parser):
        parser.add_argument("-o", "--output", help="SSL keylog file to write")

    def _initialize(self, parser, options, args):
        self._file = open(options.output, "a")

    def _usage(self):
        return "usage: %prog [options] target"

    def _needs_target(self):
        return True

    def _write(self, text):
        self._file.write(text)
        self._file.flush()

    def _start(self):
        self._update_status("Attached")

        def on_message(message, data):
            self._reactor.schedule(lambda: self._on_message(message, data))

        self._client_random_cache = set()

        self._script = self._session.create_script(self._agent())
        self._script.on("message", on_message)
        self._script.set_log_handler(self._log)

        self._update_status("Loading script...")
        self._script.load()
        self._update_status("Loaded script")

    def _log(self, level, text):
        ConsoleApplication._log(self, level, text)

    def _on_message(self, message, data):
        if message["type"] == "send":
            if message["payload"] == "session":
                self._on_session(data)
                return

        print(message)

    def _on_session(self, data):
        client_random_data = data[:32]

        if not self._cache_client_random(client_random_data):
            return

        asn1Sessiondata = data[32:]

        asn1Sequence, _ = decoder.decode(asn1Sessiondata)

        # session_id = asn1Sequence[3].asOctets()
        master_key = asn1Sequence[4].asOctets()

        self._keylog(client_random_data, master_key)

    def _keylog(self, client_random_data, master_key):
        try:
            keylog_str = self._keylog_str(client_random_data, master_key)
        except ValueError as e:
            self._log("warning", "Ignored key log: {}".format(e))
            return

        self._log("info", "Logging SSL session: {}".format(keylog_str))
        self._write(keylog_str + "\n")

    def _cache_client_random(self, client_random):
        if client_random in self._client_random_cache:
            return False

        self._client_random_cache.add(client_random)
        return True

    @classmethod
    def _keylog_str(cls, client_random_data, master_key):
        """
        Generate a log line in the NSS Key Log Format
        https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html

        :param client_random_data:
        :param master_key:
        :return: formatted log line
        """
        if len(client_random_data) != cls.CLIENT_RANDOM_LENGTH:
            raise ValueError("Client random length is incorrect")

        if len(master_key) != cls.MASTER_KEY_LENGTH:
            raise ValueError("Master Key length is incorrect")

        return "CLIENT_RANDOM {} {}".format(
            client_random_data.hex(),
            master_key.hex(),
        )

    @staticmethod
    def _agent():
        with open(AGENT_FILENAME) as f:
            return f.read()


def main():
    app = Application()
    app.run()


if __name__ == "__main__":
    main()
