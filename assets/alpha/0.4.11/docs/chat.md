# Компоненты чата

Публичные компоненты: ChatMessage, ChatButton, ChatInput, ChatComposer, ChatThread, ChatSurface.

- ChatMessage — текст, время, направление сообщения и необязательные действия. Без обработчиков группа действий не создаётся.
- ChatButton — варианты plain, emoji, attach, record, send. Можно передать icon, label, disabled, pressed, onPress. Все варианты используют одну реализацию.
- ChatInput — поле вместе с подложкой. onEmoji добавляет левую кнопку; children — правые кнопки. Отступы принадлежат полю, стили кнопок — ChatButton.
- ChatComposer — готовая композиция ChatInput и ChatButton. Управляется value/onValueChange, onSend, onAttach, onRecord, onEmoji.
- ChatThread — журнал сообщений с aria-live.
- ChatSurface — общая область вертикального градиента для сообщений и отправки.

В Qwik обработчики имеют суффикс $. Данные и операции с файлами/аудио контролируются приложением.

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

## Миграция исторических выпусков на 0.4.0

Номер относится к истории выпусков, а не к версии текущего workspace. Версию установленной библиотеки проверяй в `@alpha/core/catalog.json`.

ChatBubble заменён ChatMessage. ChatMessageActions — необязательные обработчики ChatMessage. ChatEmojiButton / ChatAttachButton / ChatRecordButton / ChatSendButton заменены ChatButton с соответствующим variant. ChatInputSurface и ChatInputActions стали внутренней разметкой ChatInput. Старые публичные экспорты удалены.

В исходном репозитории канонические компоненты находятся в `source/components/chat/*.mjs`; адаптеры генерируются в `packages/<framework>/src/components/*.tsx`. Не редактируй сгенерированные файлы. В установленном пакете используй типы адаптера и `@alpha/core/catalog.json`.

Группировка: передавай ChatMessage timestamp (Unix-время в миллисекундах) и author (стабильный идентификатор автора). ChatThread объединяет соседние сообщения одного автора и направления при интервале <= 30000 мс. У группы общие внутренние углы; время видно только на последнем сообщении. >30 секунд, другой автор или направление начинают новую группу. Без timestamp сообщение остаётся отдельным; строка time используется только для отображения.

При timestamp видимая подпись времени вычисляется автоматически: now, 1m, 1h, 24h, 2d. Она обновляется без повторного открытия чата. Полная дата доступна через title/datetime; time используется только при отсутствии timestamp.
