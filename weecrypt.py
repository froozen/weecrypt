#!/usr/bin/env python2

import weechat
import subprocess
from os import path
import json

weechat.register("weecrypt", "shak-mar", "0.1", "None",
                 "asymmetric encryption for weechat using gpg", "", "")

############################################################
#  Global variables                                        #
############################################################

channel_whitelist = []
gpg_identifiers = {}
max_length = 300
buffers = {}
config_path = "~/.weecrypt.json"

# Load the configuration
if path.isfile(path.expanduser(config_path)):
    with open(path.expanduser(config_path)) as f:
        config = json.loads(f.read())
        channel_whitelist = config["channels"]
        gpg_identifiers = config["gpg_identifiers"]

else:
    weechat.prnt("",
                 "Error: Cant find configuration file at: %s." % config_path)


############################################################
#  Helper functions                                        #
############################################################

def my_nick(server_name):
    """Retrieve your own nick"""

    return weechat.info_get("irc_nick", server_name)


def other_nicks(channel_name, server_name):
    """Return all nicks in a channel, except your own"""

    nicks = []
    infolist = weechat.infolist_get("irc_nick", "",
                                    server_name + "," + channel_name)
    rc = weechat.infolist_next(infolist)
    while rc:
        nick = weechat.infolist_string(infolist, "name")
        if nick != my_nick(server_name):
            nicks.append(nick)
        rc = weechat.infolist_next(infolist)

    return nicks


def parse_message(irc_message, server=None):
    """Parse an IRC message into a useable format"""

    # parse the message
    message_dict = {"message": irc_message}
    parsed = weechat.info_get_hashtable("irc_message_parse", message_dict)
    if server:
        parsed["server"] = server
    # remove the channel part from PRIVMSG arguments
    message = ":".join(parsed["arguments"].split(":")[1:])
    return(parsed, message)


def encryption_target(parsed, server_name):
    """Message qualifies for en- or decryption"""

    channel = parsed["channel"]
    return\
        channel in channel_whitelist or\
        channel in gpg_identifiers or\
        (channel == my_nick(server_name) and parsed["nick"] in gpg_identifiers)


def run_cmd(command, stdin=None):
    """Run a command and return wether it failed and its output"""

    # Run the command
    p = subprocess.Popen(command,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    encoded, err = [None, None]
    # Pipe stdin into the running command, if present
    if stdin:
        stdin = unicode(stdin, "utf-8")
        encoded, err = p.communicate(stdin.encode("utf-8"))
    else:
        encoded, err = p.communicate()

    if p.returncode == 0:
        encoded = encoded.decode("utf-8").strip()
        return [encoded, True]

    else:
        err = err.decode().strip()
        return [err, False]

############################################################
#  En- and Decryption functions                            #
############################################################

def gpg_encrypt(message, parsed):
    """Encrypt a message for all possible recipients"""

    # Set the correct to_nicks
    to_nicks = []
    if parsed["channel"].startswith("#"):
        to_nicks = other_nicks(parsed["channel"], parsed["server"])
    else:
        to_nicks = [parsed["channel"]]

    # Assemble the command
    command = ["gpg2", "--armor", "--encrypt", "--batch", "--no-tty"]
    for nick in to_nicks:
        if nick in gpg_identifiers:
            command.extend(["--recipient", gpg_identifiers[nick]])

    # Only encrypt if there are receipients
    if "--recipient" in command:
        return run_cmd(command, stdin=message)

    return ["", False]


def gpg_decrypt(message):
    """Decrypt a received message"""

    return run_cmd(["gpg2", "--armor", "--decrypt", "--batch", "--no-tty"],
                   stdin=message)




############################################################
#  Signal functions                                        #
############################################################

def create_signal(parsed, type, content):
    """Create a signal of a supplied type, containing the supplied content"""

    def build_message(message):
        return "PRIVMSG %s :%s" % (parsed["channel"], message)

    # Create the basic signal
    new_signal = "%s:%s:%s" % (type, content, type)
    # Encode the newlines, as they are not allowed by the IRC protocol
    new_signal = new_signal.replace("\n", "\\n", -1)

    # The signal will probably have to be split into multiple chunks
    messages = []

    chunks = len(new_signal) / max_length
    if len(new_signal) % max_length != 0:
        chunks += 1

    for i in range(chunks):
        chunk = new_signal[max_length * i:max_length * (i + 1)]
        messages.append(build_message(chunk))

    return "\n".join(messages)


def is_signal(text):
    """Check wether a buffered text is a complete signal"""

    split = text.split(":")
    if len(split) >= 3:
        return split[0] == split[-1]
    return False


def parse_signal(signal):
    """Parse a valid signal into its type and content"""

    split = signal.split(":")
    type = split[0]
    content = ":".join(split[1:-1])
    # Put the newlines back
    content = content.replace("\\n", "\n", -1)

    return [type, content]


############################################################
#  Weechat callbacks                                       #
############################################################

def in_modifier(data, modifier, server_name, irc_message):
    """Modify how received IRC messages are displayed"""

    global buffers

    parsed, message = parse_message(irc_message, server=server_name)
    buffer_id = "%s-%s-%s" % (parsed["nick"], parsed["channel"], server_name)

    # Continue only if it's an encryption target
    if not encryption_target(parsed, server_name):
        return irc_message

    def build_message(message):
        return ":%s PRIVMSG %s :%s" % \
               (parsed["host"], parsed["channel"], message)

    # Start buffering
    if buffer_id not in buffers:
        buffers[buffer_id] = ""

    # Currently buffering
    if buffer_id in buffers:
        buffers[buffer_id] += message

        # Finished buffering
        if is_signal(buffers[buffer_id]):
            type, content = parse_signal(buffers[buffer_id])
            del buffers[buffer_id]

            # It's an encrypted message
            if type == "crypt":
                result, success = gpg_decrypt(content)
                if success:
                    return build_message(result)

                else:
                    for line in result.splitlines():
                        weechat.prnt("", "Error: %s" % line)
                    return build_message("Error: Decryption failed.")

            # Report the error
            else:
                weechat.prnt("", "Error: Unknown type: %s" % type)
                return ""

        # Don't print anything while buffering
        else:
            return ""

    return build_message("<unencrypted>: %s" % message)

weechat.hook_modifier("irc_in2_privmsg", "in_modifier", "")


def out_modifier(data, modifier, server_name, irc_message):
    """Modifie how IRC messages are sent"""

    def build_message(message):
        return "PRIVMSG %s :%s" % (parsed["channel"], message)

    parsed, message = parse_message(irc_message, server=server_name)

    # Don't encrypt messages from unencrypted_cmd
    if message.startswith("<unencrypted>: "):
        return build_message(message[15:])

    # Continue only if it's an encryption target
    if not encryption_target(parsed, server_name):
        return irc_message

    # Try to encrypt the message
    result, success = gpg_encrypt(message, parsed)
    if not success:
        # Print the error
        for line in result.splitlines():
            weechat.prnt("", "Error: %s" % line)
            return ""

    else:
        return create_signal(parsed, "crypt", result)

weechat.hook_modifier("irc_out_privmsg", "out_modifier", "")


############################################################
#  Weechat commands                                        #
############################################################

def unencrypted_cmd(data, buffer, args):
    """Send an unencrypted message"""

    weechat.command(buffer, "<unencrypted>: %s" % "".join(args))
    return weechat.WEECHAT_RC_OK

weechat.hook_command("unencrypted", "sends an unencrypted message",
                     "<message>", "message: message to be sent",
                     "", "unencrypted_cmd", "")
