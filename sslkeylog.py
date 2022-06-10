#!/usr/bin/env python3
import os

from frida_tools.application import ConsoleApplication

from pyasn1.codec.der import decoder

AGENT_FILENAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.js")


class Application(ConsoleApplication):
    SESSION_ID_LENGTH = 32
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

        self._session_cache = set()

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
        asn1Sequence, _ = decoder.decode(data)

        session_id = asn1Sequence[3].asOctets()
        master_key = asn1Sequence[4].asOctets()

        self._keylog(session_id, master_key)

    def _cache_session(self, session_id):
        if session_id in self._session_cache:
            return False

        self._session_cache.add(session_id)
        return True

    def _keylog(self, session_id, master_key):
        # The hooks can catch the SSL session in an uninitialized state
        if not session_id:
            self._log("warning", "Uninitialized Session ID: {}".format(master_key.hex()))
            return False

        if not self._cache_session(session_id):
            return

        try:
            keylog_str = self._keylog_str(session_id, master_key)
        except ValueError as e:
            self._log("warning", "Ignored key log: {}".format(e))
            return

        self._log("info", "Logging SSL session: {}".format(keylog_str))
        self._write(keylog_str + "\n")

    @classmethod
    def _keylog_str(cls, session_id, master_key):
        if len(session_id) != cls.SESSION_ID_LENGTH:
            raise ValueError("Session ID length is incorrect")

        if len(master_key) != cls.MASTER_KEY_LENGTH:
            raise ValueError("Master Key length is incorrect")

        return "RSA Session-ID:{} Master-Key:{}".format(
            session_id.hex(),
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
