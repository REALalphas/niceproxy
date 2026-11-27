# Chat components

Public components: ChatMessage, ChatButton, ChatInput, ChatComposer, ChatThread, ChatSurface.

- ChatMessage — text, timestamp, message direction, and optional actions. Without handlers, the action group is not created.
- ChatButton — variants plain, emoji, attach, record, send. Accepts icon, label, disabled, pressed, onPress. All variants share one implementation.
- ChatInput — input field together with its backdrop. onEmoji adds the left button; children are the right-side buttons. Padding belongs to the input; button styles belong to ChatButton.
- ChatComposer — ready-made composition of ChatInput and ChatButton. Controlled via value/onValueChange, onSend, onAttach, onRecord, onEmoji.
- ChatThread — message log with aria-live.
- ChatSurface — shared vertical gradient area for messages and sending.

In Qwik, handlers have the $ suffix. Data and file/audio operations are controlled by the application.

```tsx
<ChatSurface>
  <ChatThread>
    <ChatMessage text="lorem ipsum" time="24h" />
    <ChatMessage text="lorem" outgoing time="1h" onReply={reply} />
  </ChatThread>
  <ChatComposer value={draft} onValueChange={setDraft}
    onEmoji={emoji} onAttach={attach} onRecord={record} onSend={send} />
</ChatSurface>
```

## Migration from historical releases to 0.4.0

The version number refers to release history, not the current workspace version. Check the installed library version in `@alpha/core/catalog.json`.

ChatBubble was replaced by ChatMessage. ChatMessageActions became optional ChatMessage handlers. ChatEmojiButton / ChatAttachButton / ChatRecordButton / ChatSendButton were replaced by ChatButton with the corresponding variant. ChatInputSurface and ChatInputActions became internal markup of ChatInput. The old public exports have been removed.

In the source repository, canonical components live in `source/components/chat/*.mjs`; adapters are generated in `packages/<framework>/src/components/*.tsx`. Do not edit generated files. In an installed package, use the adapter types and `@alpha/core/catalog.json`.

Grouping: pass ChatMessage a timestamp (Unix time in milliseconds) and author (stable author identifier). ChatThread merges adjacent messages from the same author and direction within an interval <= 30000 ms. A group shares inner corners; the time is visible only on the last message. >30 seconds, a different author, or a different direction starts a new group. Without a timestamp, a message remains standalone; the time string is used for display only.

When timestamp is provided, the visible time label is computed automatically: now, 1m, 1h, 24h, 2d. It updates without reopening the chat. The full date is available via title/datetime; time is used only when timestamp is absent.
