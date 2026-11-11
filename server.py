"""Yahoo Mail MCP server.

Exposes a Yahoo mailbox to Claude over IMAP/SMTP as a remote MCP server
(streamable HTTP). Auth is a long secret in the URL path, so the connector
URL itself is the credential: https://<host>/<MCP_SECRET>/mcp

Required environment variables:
  YAHOO_EMAIL          your full Yahoo address
  YAHOO_APP_PASSWORD   an app password generated in Yahoo account security
  MCP_SECRET           long random string (32+ chars) that forms the URL path
Optional:
  YAHOO_NAME           display name on outgoing mail
  PORT                 port to listen on (default 8000)
"""

from __future__ import annotations

import functools
import io
import os
import smtplib
import sys
from contextlib import contextmanager
from datetime import date, datetime
from email import message_from_bytes, policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from html.parser import HTMLParser

import imapclient
import uvicorn
from imapclient import IMAPClient
from imapclient.imapclient import ARCHIVE, DRAFTS, JUNK, SENT, TRASH
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.responses import PlainTextResponse

IMAP_HOST, IMAP_PORT = "imap.mail.yahoo.com", 993
SMTP_HOST, SMTP_PORT = "smtp.mail.yahoo.com", 465

EMAIL = os.environ.get("YAHOO_EMAIL", "")
APP_PASSWORD = os.environ.get("YAHOO_APP_PASSWORD", "").replace(" ", "")
DISPLAY_NAME = os.environ.get("YAHOO_NAME", "")
SECRET = os.environ.get("MCP_SECRET", "")

# Special folders: IMAP special-use flag, then Yahoo's usual names as fallback.
SPECIAL = {
    "sent": (SENT, ["Sent"]),
    "drafts": (DRAFTS, ["Draft", "Drafts"]),
    "trash": (TRASH, ["Trash"]),
    "archive": (ARCHIVE, ["Archive"]),
    "spam": (JUNK, ["Bulk", "Bulk Mail", "Spam"]),
}

mcp = MCPServer(
    "Yahoo Mail",
    instructions=(
        "Tools for the user's Yahoo Mail account. Folder arguments accept real "
        "folder names or the aliases inbox, sent, drafts, trash, archive, spam. "
        "Messages are identified by a UID that is only valid within its folder. "
        "Confirm with the user before sending mail unless they asked you to send."
    ),
)


# ---------------------------------------------------------------- helpers ---

@contextmanager
def imap():
    """Open a logged-in IMAP session for the duration of one tool call."""
    client = IMAPClient(IMAP_HOST, port=IMAP_PORT, ssl=True, timeout=30)
    try:
        try:
            client.login(EMAIL, APP_PASSWORD)
        except Exception as exc:
            raise RuntimeError(
                "Yahoo rejected the login. Check YAHOO_EMAIL and that "
                "YAHOO_APP_PASSWORD is a current app password (not the "
                f"account password). Server said: {exc}"
            ) from exc
        yield client
    finally:
        try:
            client.logout()
        except Exception:
            pass


def resolve_folder(client: IMAPClient, folder: str) -> str:
    """Map an alias (inbox, sent, drafts, ...) to the real folder name."""
    key = folder.strip().lower()
    if key == "inbox":
        return "INBOX"
    if key in SPECIAL:
        flag, fallbacks = SPECIAL[key]
        found = client.find_special_folder(flag)
        if found:
            return found
        for name in fallbacks:
            if client.folder_exists(name):
                return name
        raise ValueError(f"Could not find the {key} folder in this mailbox.")
    return folder


def decode(value) -> str:
    """Decode a possibly MIME-encoded header value to text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def fmt_addresses(addresses) -> list[str]:
    out = []
    for a in addresses or []:
        mailbox = (a.mailbox or b"").decode(errors="replace")
        host = (a.host or b"").decode(errors="replace")
        addr = f"{mailbox}@{host}" if host else mailbox
        name = decode(a.name)
        out.append(f"{name} <{addr}>" if name else addr)
    return out


class _TextExtractor(HTMLParser):
    """Minimal HTML-to-text converter for message bodies."""

    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "blockquote"}

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self.skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    lines = [" ".join(line.split()) for line in "".join(parser.parts).splitlines()]
    out, blank = [], False
    for line in lines:
        if line:
            out.append(line)
            blank = False
        elif not blank:
            out.append("")
            blank = True
    return "\n".join(out).strip()


def body_text(msg) -> str:
    """Best plain-text rendering of a message body."""
    plain = msg.get_body(preferencelist=("plain",))
    text = ""
    if plain is not None:
        try:
            text = plain.get_content().strip()
        except Exception:
            text = ""
    if len(text) < 50:  # missing or a "view this in HTML" stub
        html = msg.get_body(preferencelist=("html",))
        if html is not None:
            try:
                converted = html_to_text(html.get_content())
                if len(converted) > len(text):
                    text = converted
            except Exception:
                pass
    return text


def fetch_message(client: IMAPClient, uid: int):
    data = client.fetch([uid], ["BODY.PEEK[]", "FLAGS"])
    if uid not in data:
        raise ValueError(f"No message with UID {uid} in this folder.")
    raw = data[uid][b"BODY[]"]
    flags = [f.decode() if isinstance(f, bytes) else str(f) for f in data[uid][b"FLAGS"]]
    return message_from_bytes(raw, policy=policy.default), flags


def parse_date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def build_message(
    client: IMAPClient | None,
    to: list[str],
    subject: str,
    body: str,
    cc: list[str] | None,
    bcc: list[str] | None,
    reply_to_uid: int | None,
    reply_folder: str,
    quote_original: bool,
) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((DISPLAY_NAME, EMAIL)) if DISPLAY_NAME else EMAIL
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if bcc:
        msg["Bcc"] = ", ".join(bcc)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=EMAIL.split("@")[-1] or "yahoo.com")

    if reply_to_uid is not None and client is not None:
        client.select_folder(resolve_folder(client, reply_folder), readonly=True)
        original, _ = fetch_message(client, reply_to_uid)
        orig_id = original.get("Message-ID", "")
        if orig_id:
            msg["In-Reply-To"] = orig_id
            refs = f'{original.get("References", "")} {orig_id}'.strip()
            msg["References"] = refs
        if not subject:
            orig_subject = str(original.get("Subject", ""))
            subject = orig_subject if orig_subject.lower().startswith("re:") else f"Re: {orig_subject}"
        if quote_original:
            quoted = "\n".join(f"> {line}" for line in body_text(original).splitlines())
            body = (
                f'{body}\n\nOn {original.get("Date", "")}, '
                f'{original.get("From", "")} wrote:\n{quoted}'
            )

    msg["Subject"] = subject
    msg.set_content(body)
    return msg


# ------------------------------------------------------------------ tools ---

READ = ToolAnnotations(readOnlyHint=True)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False)


def tool(annotations: ToolAnnotations):
    """Register a tool whose failures reach Claude as readable messages.

    The SDK hides the text of unexpected exceptions, so convert them to
    ToolError, which is passed through to the model.
    """

    def register(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except ToolError:
                raise
            except Exception as exc:
                raise ToolError(f"{type(exc).__name__}: {exc}") from exc

        return mcp.tool(annotations=annotations)(wrapper)

    return register


@tool(READ)
def list_folders() -> list[dict]:
    """List every folder in the mailbox with its total and unread counts."""
    with imap() as client:
        out = []
        for flags, _delim, name in client.list_folders():
            if b"\\Noselect" in flags:
                continue
            try:
                status = client.folder_status(name, ["MESSAGES", "UNSEEN"])
                out.append(
                    {
                        "name": name,
                        "messages": status.get(b"MESSAGES", 0),
                        "unread": status.get(b"UNSEEN", 0),
                    }
                )
            except Exception:
                out.append({"name": name})
        return out


@tool(READ)
def search_emails(
    folder: str = "inbox",
    from_address: str | None = None,
    to_address: str | None = None,
    subject: str | None = None,
    text: str | None = None,
    since: str | None = None,
    before: str | None = None,
    unread_only: bool = False,
    flagged_only: bool = False,
    limit: int = 25,
) -> dict:
    """Search one folder and return message summaries, newest first.

    All filters are optional and combine with AND; with none, returns the
    latest messages. `text` matches anywhere in headers or body. `since` and
    `before` are dates as YYYY-MM-DD (since is inclusive, before is exclusive).
    Use the returned uid with read_email. Max limit is 100.
    """
    criteria: list = []
    if from_address:
        criteria += ["FROM", from_address]
    if to_address:
        criteria += ["TO", to_address]
    if subject:
        criteria += ["SUBJECT", subject]
    if text:
        criteria += ["TEXT", text]
    if since:
        criteria += ["SINCE", parse_date(since)]
    if before:
        criteria += ["BEFORE", parse_date(before)]
    if unread_only:
        criteria.append("UNSEEN")
    if flagged_only:
        criteria.append("FLAGGED")
    if not criteria:
        criteria = ["ALL"]
    needs_utf8 = any(isinstance(c, str) and not c.isascii() for c in criteria)
    limit = max(1, min(limit, 100))

    with imap() as client:
        real = resolve_folder(client, folder)
        client.select_folder(real, readonly=True)
        uids = client.search(criteria, charset="UTF-8" if needs_utf8 else None)
        total = len(uids)
        chosen = sorted(uids, reverse=True)[:limit]
        results = []
        if chosen:
            data = client.fetch(chosen, ["ENVELOPE", "FLAGS", "RFC822.SIZE"])
            for uid in chosen:
                item = data.get(uid)
                if not item:
                    continue
                env = item[b"ENVELOPE"]
                flags = item.get(b"FLAGS", ())
                results.append(
                    {
                        "uid": uid,
                        "date": env.date.isoformat() if env.date else None,
                        "from": fmt_addresses(env.from_),
                        "to": fmt_addresses(env.to),
                        "subject": decode(env.subject),
                        "unread": b"\\Seen" not in flags,
                        "flagged": b"\\Flagged" in flags,
                        "size_bytes": item.get(b"RFC822.SIZE"),
                    }
                )
        return {"folder": real, "total_matches": total, "returned": len(results), "messages": results}


@tool(READ)
def read_email(uid: int, folder: str = "inbox", max_chars: int = 20000) -> dict:
    """Read one message in full: headers, body as text, and attachment list.

    Does not mark the message as read. Long bodies are cut at max_chars.
    Use get_attachment with an attachment's index to read its contents.
    """
    with imap() as client:
        real = resolve_folder(client, folder)
        client.select_folder(real, readonly=True)
        msg, flags = fetch_message(client, uid)

    text = body_text(msg)
    attachments = []
    for i, part in enumerate(msg.iter_attachments()):
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "index": i,
                "filename": part.get_filename() or "(unnamed)",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
            }
        )
    return {
        "uid": uid,
        "folder": real,
        "date": str(msg.get("Date", "")),
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "cc": str(msg.get("Cc", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "subject": str(msg.get("Subject", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "flags": flags,
        "body": text[:max_chars],
        "body_truncated": len(text) > max_chars,
        "attachments": attachments,
    }


@tool(READ)
def get_attachment(uid: int, attachment_index: int, folder: str = "inbox", max_chars: int = 50000) -> dict:
    """Return the text of one attachment (index comes from read_email).

    Works for text formats (txt, csv, json, html, ics, ...) and PDFs with a
    text layer. Other binary formats return metadata only.
    """
    with imap() as client:
        client.select_folder(resolve_folder(client, folder), readonly=True)
        msg, _ = fetch_message(client, uid)

    parts = list(msg.iter_attachments())
    if not 0 <= attachment_index < len(parts):
        raise ValueError(f"Message has {len(parts)} attachment(s); index {attachment_index} is out of range.")
    part = parts[attachment_index]
    payload = part.get_payload(decode=True) or b""
    ctype = part.get_content_type()
    name = part.get_filename() or "(unnamed)"
    info = {"filename": name, "content_type": ctype, "size_bytes": len(payload)}

    text = None
    if ctype == "application/pdf" or name.lower().endswith(".pdf"):
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(payload))
        text = "\n\n".join((page.extract_text() or "") for page in reader.pages).strip()
        info["pages"] = len(reader.pages)
    elif ctype.startswith("text/") or ctype in ("application/json", "application/xml", "application/csv"):
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        if ctype == "text/html":
            text = html_to_text(text)

    if text is None:
        info["note"] = "Binary attachment; contents cannot be returned as text."
        return info
    info["text"] = text[:max_chars]
    info["truncated"] = len(text) > max_chars
    return info


@tool(ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True))
def send_email(
    to: list[str],
    body: str,
    subject: str = "",
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    reply_to_uid: int | None = None,
    reply_folder: str = "inbox",
    quote_original: bool = True,
) -> dict:
    """Send a plain-text email from the user's Yahoo address. Sends immediately.

    To reply in-thread, pass reply_to_uid (and reply_folder) of the message
    being answered: threading headers are set, the subject defaults to
    "Re: ..." if left empty, and the original is quoted below the body unless
    quote_original is false. `to` must still list the recipients.
    """
    if not to:
        raise ValueError("At least one recipient is required.")
    if reply_to_uid is not None:
        with imap() as client:
            msg = build_message(client, to, subject, body, cc, bcc, reply_to_uid, reply_folder, quote_original)
    else:
        if not subject:
            raise ValueError("A subject is required for a new email.")
        msg = build_message(None, to, subject, body, cc, bcc, None, reply_folder, False)

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        smtp.login(EMAIL, APP_PASSWORD)
        smtp.send_message(msg)  # Bcc header is stripped by send_message
    return {"sent": True, "to": to, "cc": cc or [], "bcc": bcc or [], "subject": msg["Subject"]}


@tool(WRITE)
def create_draft(
    to: list[str],
    body: str,
    subject: str = "",
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    reply_to_uid: int | None = None,
    reply_folder: str = "inbox",
    quote_original: bool = True,
) -> dict:
    """Save an email to the Drafts folder without sending it.

    Takes the same arguments as send_email, including reply threading.
    The user can review and send the draft from Yahoo Mail.
    """
    with imap() as client:
        msg = build_message(client, to, subject, body, cc, bcc, reply_to_uid, reply_folder, quote_original)
        drafts = resolve_folder(client, "drafts")
        client.append(drafts, msg.as_bytes(), flags=[imapclient.DRAFT, imapclient.SEEN])
    return {"saved": True, "folder": drafts, "subject": msg["Subject"]}


@tool(ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def move_emails(uids: list[int], destination: str, folder: str = "inbox") -> dict:
    """Move messages from `folder` to `destination`.

    Destination can be a folder name or an alias: archive, trash, spam, inbox.
    Moving to trash is how messages are deleted; Yahoo empties Trash on its
    own schedule, so nothing is removed permanently by this tool. UIDs change
    after a move, so search the destination again before acting on them.
    """
    if not uids:
        raise ValueError("No UIDs given.")
    with imap() as client:
        source = resolve_folder(client, folder)
        dest = resolve_folder(client, destination)
        if not client.folder_exists(dest):
            client.create_folder(dest)
        client.select_folder(source)
        if client.has_capability("MOVE"):
            client.move(uids, dest)
        else:
            client.copy(uids, dest)
            client.add_flags(uids, [imapclient.DELETED], silent=True)
            if client.has_capability("UIDPLUS"):
                client.uid_expunge(uids)
            else:
                client.expunge()
    return {"moved": len(uids), "from": source, "to": dest}


@tool(WRITE)
def mark_emails(
    uids: list[int],
    folder: str = "inbox",
    read: bool | None = None,
    flagged: bool | None = None,
) -> dict:
    """Mark messages read/unread and/or starred/unstarred.

    Leave an option as null to keep it unchanged.
    """
    if not uids:
        raise ValueError("No UIDs given.")
    if read is None and flagged is None:
        raise ValueError("Set read and/or flagged.")
    with imap() as client:
        real = resolve_folder(client, folder)
        client.select_folder(real)
        if read is True:
            client.add_flags(uids, [imapclient.SEEN], silent=True)
        elif read is False:
            client.remove_flags(uids, [imapclient.SEEN], silent=True)
        if flagged is True:
            client.add_flags(uids, [imapclient.FLAGGED], silent=True)
        elif flagged is False:
            client.remove_flags(uids, [imapclient.FLAGGED], silent=True)
    return {"updated": len(uids), "folder": real, "read": read, "flagged": flagged}


# ----------------------------------------------------------------- server ---

@mcp.custom_route("/health", methods=["GET"])
async def health(_request):
    return PlainTextResponse("ok")


def create_app():
    missing = [n for n, v in (("YAHOO_EMAIL", EMAIL), ("YAHOO_APP_PASSWORD", APP_PASSWORD), ("MCP_SECRET", SECRET)) if not v]
    if missing:
        sys.exit(f"Missing environment variables: {', '.join(missing)}")
    if len(SECRET) < 32 or not SECRET.replace("-", "").replace("_", "").isalnum():
        sys.exit("MCP_SECRET must be 32+ characters using only letters, digits, - and _.")
    return mcp.streamable_http_app(
        streamable_http_path=f"/{SECRET}/mcp",
        json_response=True,
        stateless_http=True,
        host="0.0.0.0",
        # Host header is set by the hosting platform's proxy, so don't pin it.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )


if __name__ == "__main__":
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), log_level="warning")
