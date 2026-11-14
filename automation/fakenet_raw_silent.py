# FakeNet-NG's raw listeners, answering nothing. Loaded by RawListener through
# automation/fakenet-custom.ini; `make sandboxd` installs both in /etc, beside
# fakenet.ini, which names the second.
#
# RawListener is the fallback for bytes no protocol listener recognised, and
# upstream's sends them back: an echo server. A loader that asks its server
# for a payload then gets its own request as the payload. Job fca804a4 of
# 2026-11-13 (Snowlight): 40 bytes sent to 45.86.229.111:80, the same 40
# received and written into a memfd, and the run ended waiting for more.
#
# A server that accepts, reads and says nothing is what a sample meets when
# its infrastructure is up and not talking to it, and it cannot be mistaken
# for an answer. The connection still shows in the capture, and what the
# sample sent is still hexdumped to the journal (RawListener wraps recv).
import socket


def HandleTcp(sock):
    """Read until the sample closes or the listener's Timeout ends it."""
    try:
        while sock.recv(4096):
            pass
    except (socket.timeout, OSError):
        pass


def HandleUdp(sock, data, addr):
    """Nothing: RawListener has logged the datagram before it calls this."""
