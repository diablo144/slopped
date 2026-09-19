slopped

Run the supplied Linux/amd64 client with the signaling URL shown on the
challenge page:

    chmod +x peerctl
    ./peerctl --config https://SIGNALING-ENDPOINT/v1/config

Type a message to chat with the archive peer. Use /help for commands.

When stdin is piped, peerctl reads and writes JSON Lines without banners or
prompts. Pass --json to select that mode explicitly.
